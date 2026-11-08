//! WFP 独立子层内先放行管理端点，再阻断其余连接。持久规则通过事务原子替换。
use super::Outcome;
use crate::pb::Command;
use std::net::{IpAddr, SocketAddr};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

const SUBLAYER: GUID = GUID::from_u128(0x76d87151_94b3_42bd_9394_127c3b11492e);
const LAYERS: [(GUID, bool); 4] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
    (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true),
];
#[derive(Debug, PartialEq)]
struct Endpoint {
    ip: IpAddr,
    port: Option<u16>,
}
fn endpoints(values: &[String]) -> Result<Vec<Endpoint>, String> {
    if values.is_empty() || values.len() > 128 {
        return Err("放行地址须为 1–128 个数字 IP 或 IP:端口".into());
    }
    values
        .iter()
        .map(|s| {
            let ep = match s.parse::<SocketAddr>() {
                Ok(a) => Endpoint {
                    ip: a.ip(),
                    port: Some(a.port()),
                },
                Err(_) => Endpoint {
                    ip: s
                        .parse()
                        .map_err(|_| "放行地址必须是数字 IP；IPv6 端口格式为 [地址]:端口")?,
                    port: None,
                },
            };
            if ep.ip.is_unspecified() || ep.ip.is_multicast() || ep.port == Some(0) {
                return Err("放行地址或端口无效".into());
            }
            Ok(ep)
        })
        .collect()
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
        for ep in allowed.iter().filter(|e| e.ip.is_ipv6() == ipv6) {
            add_endpoint(engine, layer, ep)?;
        }
    }
    Ok(())
}
fn add_endpoint(engine: &Engine, layer: GUID, ep: &Endpoint) -> Result<(), String> {
    let mut v6 = FWP_BYTE_ARRAY16::default();
    let address = match ep.ip {
        IpAddr::V4(ip) => FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: u32::from(ip),
            },
        },
        IpAddr::V6(ip) => {
            v6.byteArray16 = ip.octets();
            FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteArray16: &mut v6,
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
        ])
        .unwrap();
        assert_eq!(eps[0].port, Some(8081));
        assert!(eps[1].ip.is_ipv6());
        assert_eq!(eps[2].port, None);
        for s in ["0.0.0.0", "::", "host:443", "192.0.2.1:0", "192.0.2.1;cmd"] {
            assert!(endpoints(&[s.into()]).is_err());
        }
        assert!(endpoints(&[]).is_err());
    }
}
