//! WFP 独立子层内先放行管理端点，再阻断其余连接。持久规则通过事务原子替换。
use super::Outcome;
use super::netblock::Net;
use crate::pb::Command;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

const SUBLAYER: GUID = GUID::from_u128(0x76d87151_94b3_42bd_9394_127c3b11492e);
const MAX_ALLOW_ENDPOINTS: usize = 128;
const TOTAL_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESOLVED: usize = 32;
const MAX_TOTAL_ENDPOINTS: usize = 256;
const MAX_INFLIGHT_DNS: usize = 8;

static INFLIGHT_DNS: AtomicUsize = AtomicUsize::new(0);

/// 在途 DNS 解析并发槽位，解析线程结束时自动归还。
struct DnsSlot;

impl DnsSlot {
    fn try_acquire() -> Option<Self> {
        let mut cur = INFLIGHT_DNS.load(Ordering::Relaxed);
        loop {
            if cur >= MAX_INFLIGHT_DNS {
                return None;
            }
            match INFLIGHT_DNS.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self),
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for DnsSlot {
    fn drop(&mut self) {
        INFLIGHT_DNS.fetch_sub(1, Ordering::Release);
    }
}
const LAYERS: [(GUID, bool); 4] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true),
];
#[derive(Debug, PartialEq)]
struct Endpoint {
    net: Net,
    port: Option<u16>,
}

fn host_net(ip: IpAddr) -> Net {
    Net::canonical(ip, if ip.is_ipv4() { 32 } else { 128 })
}

fn port_of(p: &str, ep: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) => Err(format!("放行地址端口不能为 0：{ep}")),
        Ok(port) => Ok(port),
        Err(_) => Err(format!("放行地址端口无效：{ep}")),
    }
}

/// 主机名：每段 1–63 个 ASCII 字母、数字或 `-`，不以 `-` 开头结尾，总长不超过 253
fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn system_resolve(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    (host, port)
        .to_socket_addrs()
        .map(|iter| iter.map(|a| a.ip()).collect())
        .map_err(|e| e.to_string())
}

fn resolve_hostname_with<F>(
    host: &str,
    port: Option<u16>,
    deadline: Instant,
    resolver: F,
) -> Result<Vec<Net>, String>
where
    F: Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + 'static,
{
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(format!(
            "放行地址 {host} 解析超时（已超过整条隔离指令截止时间）"
        ));
    };
    if remaining.is_zero() {
        return Err(format!(
            "放行地址 {host} 解析超时（已超过整条隔离指令截止时间）"
        ));
    }
    let Some(slot) = DnsSlot::try_acquire() else {
        return Err(format!(
            "在途 DNS 解析已达并发上限（{MAX_INFLIGHT_DNS}），拒绝解析 {host}"
        ));
    };
    let owned_host = host.to_string();
    let resolve_port = port.unwrap_or(0);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _slot = slot;
        let res = resolver(&owned_host, resolve_port);
        let _ = tx.send(res);
    });
    let ips = match rx.recv_timeout(remaining) {
        Ok(Ok(ips)) => ips,
        Ok(Err(e)) => return Err(format!("放行地址 {host} 解析失败：{e}")),
        Err(_) => return Err(format!("放行地址 {host} 解析超时")),
    };
    validate_resolved_nets(host, ips)
}

fn validate_resolved_nets(
    host: &str,
    ips: impl IntoIterator<Item = IpAddr>,
) -> Result<Vec<Net>, String> {
    let mut nets: Vec<Net> = ips
        .into_iter()
        .filter(|ip| !ip.is_unspecified() && !ip.is_multicast())
        .map(host_net)
        .collect();
    nets.sort();
    nets.dedup();
    if nets.is_empty() {
        return Err(format!("放行地址 {host} 没有解析出有效地址"));
    }
    if nets.len() > MAX_RESOLVED {
        return Err(format!(
            "放行地址 {host} 解析出 {} 个地址，超过上限 {MAX_RESOLVED}，拒绝截断以免丢失控制端地址",
            nets.len()
        ));
    }
    Ok(nets)
}

fn parse_endpoint_with<F>(ep: &str, deadline: Instant, resolver: F) -> Result<Vec<Endpoint>, String>
where
    F: Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + 'static,
{
    let trimmed = ep.trim();
    if trimmed.is_empty() {
        return Err("放行地址为空".into());
    }
    if let Ok(a) = trimmed.parse::<SocketAddr>() {
        if a.ip().is_unspecified() || a.ip().is_multicast() || a.port() == 0 {
            return Err(format!("放行地址或端口无效：{ep}"));
        }
        return Ok(vec![Endpoint {
            net: host_net(a.ip()),
            port: Some(a.port()),
        }]);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(format!("放行地址无效：{ep}"));
        }
        return Ok(vec![Endpoint {
            net: host_net(ip),
            port: None,
        }]);
    }
    if let Some((addr, prefix)) = trimmed.split_once('/') {
        let invalid = || format!("放行网段无效（须为 地址/前缀长度）：{ep}");
        let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix == 0 || prefix > max_prefix {
            return Err(invalid());
        }
        let net = Net::canonical(addr, prefix);
        if net.addr.is_multicast() {
            return Err(format!("放行网段无效：{ep}"));
        }
        return Ok(vec![Endpoint { net, port: None }]);
    }
    let (host, port) = match trimmed.rsplit_once(':') {
        Some((h, p)) => (h, Some(port_of(p, ep)?)),
        None => (trimmed, None),
    };
    if !hostname(host) {
        return Err(format!(
            "放行地址无效（须为 IP、IP:端口、网段或主机名[:端口]）：{ep}"
        ));
    }
    let nets = resolve_hostname_with(host, port, deadline, resolver)?;
    Ok(nets.into_iter().map(|net| Endpoint { net, port }).collect())
}

fn endpoints(values: &[String]) -> Result<Vec<Endpoint>, String> {
    endpoints_with(values, TOTAL_RESOLVE_TIMEOUT, system_resolve)
}

fn endpoints_with<F>(
    values: &[String],
    total_timeout: Duration,
    resolver: F,
) -> Result<Vec<Endpoint>, String>
where
    F: Fn(&str, u16) -> Result<Vec<IpAddr>, String> + Send + Sync + Clone + 'static,
{
    if values.is_empty() || values.len() > MAX_ALLOW_ENDPOINTS {
        return Err(format!(
            "放行地址须为 1–{MAX_ALLOW_ENDPOINTS} 项（IP、IP:端口、网段或主机名[:端口]）"
        ));
    }
    let deadline = Instant::now() + total_timeout;
    let mut out = Vec::with_capacity(values.len());
    for s in values {
        out.extend(parse_endpoint_with(s, deadline, resolver.clone())?);
        if out.len() > MAX_TOTAL_ENDPOINTS {
            return Err(format!(
                "放行地址展开后共 {} 条，超过上限 {MAX_TOTAL_ENDPOINTS}，拒绝截断以免丢失控制端地址",
                out.len()
            ));
        }
    }
    Ok(out)
}
pub fn isolate(cmd: &Command) -> Outcome {
    let allowed = match endpoints(&cmd.allow_endpoints) {
        Ok(v) => v,
        Err(e) => return Outcome::failed(e),
    };
    match replace(Some(&allowed)) {
        Ok(()) => Outcome::ok(format!(
            "已通过 WFP 隔离，放行 {}",
            cmd.allow_endpoints.join(", ")
        )),
        Err(e) => Outcome::failed(e),
    }
}
pub fn unisolate(_cmd: &Command) -> Outcome {
    if let Err(e) = replace(None) {
        return Outcome::failed(e);
    }
    match remove_legacy() {
        Ok(()) => Outcome::ok("已解除隔离"),
        Err(e) => Outcome::failed(e),
    }
}
struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: Engine 只包裹 FwpmEngineOpen0 成功返回的会话句柄（失败时 ? 提前返回、不构造），
        // 不可 Clone，Drop 只执行一次。
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
fn check(code: u32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("WFP 操作失败: 0x{code:08x}"))
    }
}
fn open_engine() -> Result<Engine, String> {
    let mut handle = null_mut();
    // 所有指针仅在同步调用期间借用，WFP 复制规则数据。
    // SAFETY: 服务器名、认证标识与会话参数传空指针表示本机、当前身份、默认会话，是 API 允许的用法；
    // handle 是栈上出参，成功时写入引擎句柄。
    unsafe {
        check(FwpmEngineOpen0(
            null(),
            RPC_C_AUTHN_WINNT,
            null(),
            null(),
            &mut handle,
        ))?;
    }
    Ok(Engine(handle))
}

/// 本机当前是否处于隔离：隔离时建子层，解除时连子层一起删，子层在就是隔离着
pub fn active() -> bool {
    let Ok(engine) = open_engine() else {
        return false;
    };
    let mut sublayer: *mut FWPM_SUBLAYER0 = null_mut();
    // SAFETY: engine.0 有效；&SUBLAYER 指向静态 GUID；sublayer 是栈上出参，成功时由系统分配
    let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER, &mut sublayer) };
    if code != 0 {
        return false;
    }
    // SAFETY: 调用成功时 sublayer 指向系统分配的内存，只在这里释放一次，之后不再使用
    unsafe {
        FwpmFreeMemory0(&mut sublayer as *mut _ as *mut _);
    }
    true
}

fn replace(allowed: Option<&[Endpoint]>) -> Result<(), String> {
    let engine = open_engine()?;
    // SAFETY: engine.0 是上面成功打开、由 engine 持有的会话句柄，在本函数内一直有效。
    unsafe {
        check(FwpmTransactionBegin0(engine.0, 0))?;
    }
    // SAFETY: engine.0 有效；提交只作用于本会话已开启的事务。
    let result =
        update(&engine, allowed).and_then(|()| unsafe { check(FwpmTransactionCommit0(engine.0)) });
    if result.is_err() {
        // SAFETY: 同上：engine.0 有效，回滚本会话已开启但未提交的事务。
        unsafe {
            FwpmTransactionAbort0(engine.0);
        }
    }
    result
}
fn update(engine: &Engine, allowed: Option<&[Endpoint]>) -> Result<(), String> {
    remove_owned(engine)?;
    let Some(allowed) = allowed else {
        // SAFETY: engine.0 是调用方持有的有效会话句柄；&SUBLAYER 指向静态 GUID，调用期间有效。
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER) };
        return if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {
            Ok(())
        } else {
            check(code)
        };
    };
    let mut name: Vec<u16> = "OpenXDR 隔离\0".encode_utf16().collect();
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER,
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        weight: 0x8000,
        ..Default::default()
    };
    // SAFETY: sublayer 及其引用的 name 缓冲都是本函数的局部变量，同步调用期间存活，WFP 内部复制数据；
    // 安全描述符传空表示默认。
    let code = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, null_mut()) };
    if code != FWP_E_ALREADY_EXISTS as u32 {
        check(code)?;
    }
    for (layer, ipv6) in LAYERS {
        add_filter(engine, layer, false, &mut [])?;
        let mut loopback = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        }];
        add_filter(engine, layer, true, &mut loopback)?;
        for ep in allowed.iter().filter(|e| e.net.addr.is_ipv6() == ipv6) {
            add_endpoint(engine, layer, ep)?;
        }
    }
    Ok(())
}
fn add_endpoint(engine: &Engine, layer: GUID, ep: &Endpoint) -> Result<(), String> {
    let mut v6 = FWP_BYTE_ARRAY16::default();
    let mut v4_mask = FWP_V4_ADDR_AND_MASK::default();
    let mut v6_mask = FWP_V6_ADDR_AND_MASK::default();
    let address = match ep.net.addr {
        IpAddr::V4(ip) if ep.net.prefix == 32 => FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: u32::from(ip),
            },
        },
        IpAddr::V4(ip) => {
            v4_mask.addr = u32::from(ip);
            v4_mask.mask = u32::MAX.checked_shl(32 - ep.net.prefix as u32).unwrap_or(0);
            FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: &mut v4_mask,
                },
            }
        }
        IpAddr::V6(ip) if ep.net.prefix == 128 => {
            v6.byteArray16 = ip.octets();
            FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteArray16: &mut v6,
                },
            }
        }
        IpAddr::V6(ip) => {
            v6_mask.addr = ip.octets();
            v6_mask.prefixLength = ep.net.prefix;
            FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: &mut v6_mask,
                },
            }
        }
    };
    let mut conditions = vec![FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: address,
    }];
    if let Some(port) = ep.port {
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 },
            },
        });
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        });
    }
    add_filter(engine, layer, true, &mut conditions)
}
fn add_filter(
    engine: &Engine,
    layer: GUID,
    permit: bool,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), String> {
    let mut name: Vec<u16> = "OpenXDR 隔离规则\0".encode_utf16().collect();
    let mut weight: u64 = if permit { 100 } else { 1 };
    let filter = FWPM_FILTER0 {
        layerKey: layer,
        subLayerKey: SUBLAYER,
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight,
            },
        },
        action: FWPM_ACTION0 {
            r#type: if permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            },
            ..Default::default()
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: filter 引用的 name、weight 与 conditions 都比这次同步调用活得久，numFilterConditions
    // 与 conditions.len() 一致；WFP 复制规则后不再持有这些指针，出参 ID 与安全描述符传空表示不需要。
    unsafe { check(FwpmFilterAdd0(engine.0, &filter, null_mut(), null_mut())) }
}
fn remove_owned(engine: &Engine) -> Result<(), String> {
    for (layer, _) in LAYERS {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: layer,
            actionMask: u32::MAX,
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            ..Default::default()
        };
        let mut enumeration = null_mut();
        // SAFETY: engine.0 有效；template 是栈上已初始化的枚举模板，enumeration 是栈上出参。
        unsafe {
            check(FwpmFilterCreateEnumHandle0(
                engine.0,
                &template,
                &mut enumeration,
            ))?;
        }
        let result = remove_enumerated(engine, enumeration);
        // SAFETY: enumeration 是上面成功创建的枚举句柄（失败时 ? 已提前返回），只在这里销毁一次。
        unsafe {
            FwpmFilterDestroyEnumHandle0(engine.0, enumeration);
        }
        result?;
    }
    Ok(())
}
fn remove_enumerated(engine: &Engine, enumeration: HANDLE) -> Result<(), String> {
    loop {
        let mut entries = null_mut();
        let mut count = 0;
        // SAFETY: engine.0 与 enumeration 都有效；entries / count 是栈上出参，系统分配的数组需由
        // FwpmFreeMemory0 释放。
        unsafe {
            check(FwpmFilterEnum0(
                engine.0,
                enumeration,
                128,
                &mut entries,
                &mut count,
            ))?;
        }
        if count == 0 {
            if !entries.is_null() {
                // SAFETY: entries 非空，是 FwpmFilterEnum0 分配的数组，只在这里释放一次，之后不再使用。
                unsafe {
                    FwpmFreeMemory0(&mut entries as *mut _ as *mut _);
                }
            }
            return Ok(());
        }
        // SAFETY: FwpmFilterEnum0 成功时 entries 指向 count 个 FWPM_FILTER0 指针组成的数组，由系统分配，
        // 在下面 FwpmFreeMemory0 之前一直有效；ids 收集完才释放。
        let ids: Vec<u64> = unsafe { std::slice::from_raw_parts(entries, count as usize) }
            .iter()
            .filter_map(|entry| {
                // SAFETY: 数组里每个元素都指向系统分配、与数组同生命周期的有效 FWPM_FILTER0，只读字段。
                let filter = unsafe { &**entry };
                (same_guid(filter.subLayerKey, SUBLAYER)).then_some(filter.filterId)
            })
            .collect();
        // SAFETY: entries 由 FwpmFilterEnum0 分配，借用它的切片已在上面 collect 完毕，只在这里释放一次。
        unsafe {
            FwpmFreeMemory0(&mut entries as *mut _ as *mut _);
        }
        for id in ids {
            // SAFETY: engine.0 有效；按值传入的过滤器 ID 不涉及内存。
            unsafe {
                check(FwpmFilterDeleteById0(engine.0, id))?;
            }
        }
    }
}
fn remove_legacy() -> Result<(), String> {
    // 只删除旧版明确命名的隔离规则，不改用户策略；不限制放行地址数量。
    let script = "$ErrorActionPreference='Stop'; Get-NetFirewallRule | Where-Object { $_.DisplayName -match '^OpenXDR-Isolation-(Block-(in|out)|Allow-[0-9]+-(in|out))$' } | Remove-NetFirewallRule";
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("WFP 已解除，但旧版隔离规则清理失败，请检查管理员权限".into());
    }
    Ok(())
}

fn same_guid(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_endpoints() {
        let eps = endpoints(&[
            "192.0.2.1:8081".into(),
            "[2001:db8::1]:443".into(),
            "192.0.2.2".into(),
            "10.1.1.7/24".into(),
            "2001:db8::5/64".into(),
        ])
        .unwrap();
        assert_eq!(eps[0].port, Some(8081));
        assert_eq!(eps[0].net.prefix, 32);
        assert!(eps[1].net.addr.is_ipv6());
        assert_eq!(eps[2].port, None);
        assert_eq!(eps[3].net.render(), "10.1.1.0/24");
        assert_eq!(eps[4].net.render(), "2001:db8::/64");
        for s in [
            "0.0.0.0",
            "::",
            "0.0.0.0/0",
            "10.0.0.0/33",
            "10.0.0.0/24:443",
            "-bad.example.com",
            "192.0.2.1:0",
            "192.0.2.1;cmd",
        ] {
            assert!(endpoints(&[s.into()]).is_err(), "{s:?} 应拒绝");
        }
        assert!(endpoints(&[]).is_err());
        let local = endpoints(&["localhost:8081".into()]).unwrap();
        assert!(!local.is_empty());
        assert!(local.iter().all(|e| e.port == Some(8081)));
    }

    #[test]
    fn rejects_over_resolved_and_shares_overall_deadline() {
        let ips = (0..64u8).map(|i| IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i)));
        let err = validate_resolved_nets("many.example.com", ips).unwrap_err();
        assert!(err.contains("超过上限"), "{err}");

        let domains: Vec<String> = (0..9).map(|i| format!("h{i}.example.com:443")).collect();
        let err = endpoints_with(&domains, Duration::from_secs(2), |host, _| {
            let idx: u8 = host
                .strip_prefix('h')
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            Ok((1..=30u8)
                .map(|j| IpAddr::V4(std::net::Ipv4Addr::new(10, idx, 0, j)))
                .collect())
        })
        .unwrap_err();
        assert!(err.contains("超过上限"), "{err}");

        let slow: Vec<String> = (0..4).map(|i| format!("slow{i}.example.com:443")).collect();
        let started = Instant::now();
        let err = endpoints_with(&slow, Duration::from_millis(200), |_, _| {
            std::thread::sleep(Duration::from_millis(120));
            Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1))])
        })
        .unwrap_err();
        assert!(err.contains("超时"), "{err}");
        assert!(started.elapsed() < Duration::from_millis(450));
    }
}
