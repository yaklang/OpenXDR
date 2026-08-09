//! Windows 网络采集：订阅 Microsoft-Windows-Kernel-Network provider，
//! 只取 TcpConnect 事件（connect 发起方），与 Linux eBPF inet_sock_set_state 路径对称。
//!
//! 实机勘定（ferrisetw 打全事件 + curl 出站对拍）：事件 ID 12 是 TcpConnect，
//! 且只在本机主动 connect 时触发；10/11/18 是数据收发、13 是断连，都不要。
//! 字段为 PID/saddr/daddr/sport/dport/size；地址 ferrisetw 直接解出 IpAddr，
//! 端口是网络字节序（抓到 dport=20480 即 htons(80)），用前要转主机序。
//!
//! UDP 先不做：UDP 无连接语义，该 provider 只有按数据报的收发事件（42/43 等），
//! 每条报文一个事件，60s 采样去重前就会在回调里白耗 CPU；等确有需求再按
//! "同目标采样"的思路补，不拿半成品凑数。
//!
//! 独立 trace session：订阅失败（provider 不存在、权限不够）只降级警告，
//! 绝不影响进程采集主路。

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

use super::netwatch::{self, ConnInfo, ConnSampler};
use super::{EventSink, ProcessRegistry};

const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

/// KERNEL_NETWORK_TASK_TCPIP 下的 TcpConnect（实机勘定，见模块头注释）
const EVENT_TCP_CONNECT: u16 = 12;

pub fn spawn(agent_id: String, sink: EventSink, registry: Arc<Mutex<ProcessRegistry>>) {
    std::thread::spawn(move || run(agent_id, sink, registry));
}

fn run(agent_id: String, sink: EventSink, registry: Arc<Mutex<ProcessRegistry>>) {
    // ETW 回调要求 'static，采样表/注册表/出口全部按所有权移进闭包；
    // 注册表由 mod.rs 传入，与进程采集共享
    let sampler = Mutex::new(ConnSampler::default());

    let provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != EVENT_TCP_CONNECT {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let (Ok(pid), Ok(src), Ok(dst), Ok(sport), Ok(dport)) = (
                parser.try_parse::<u32>("PID"),
                parser.try_parse::<IpAddr>("saddr"),
                parser.try_parse::<IpAddr>("daddr"),
                parser.try_parse::<u16>("sport"),
                parser.try_parse::<u16>("dport"),
            ) else {
                return;
            };
            // 端口字段是网络字节序（实机抓到 dport=20480 即 htons(80)）
            let (sport, dport) = (u16::from_be(sport), u16::from_be(dport));
            if !reportable(src, dst) {
                return;
            }
            if !sampler
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .should_report(dst, dport)
            {
                return;
            }
            // 进程没注册过（早于 agent 启动）就现场登记，保证事件一定挂得上 GUID
            let guid = {
                let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                match reg.guid_of(pid) {
                    Some(g) => g,
                    None => reg.register(pid, None).0,
                }
            };
            sink.send(netwatch::conn_event(
                &agent_id,
                &ConnInfo {
                    pid,
                    guid: Some(guid),
                    src,
                    sport,
                    dst,
                    dport,
                },
            ));
        })
        .build();

    match UserTrace::new().enable(provider).start_and_process() {
        Ok(_trace) => {
            eprintln!("网络采集: ETW Kernel-Network TcpConnect（TCP 出站，60s 采样）");
            // trace 句柄保活；agent 退出即进程结束，无需额外清理
            std::thread::park();
        }
        Err(e) => eprintln!("网络采集不可用（{e:?}），进程采集不受影响"),
    }
}

/// 本机自娱自乐与未绑定地址的连接没有检测价值：loopback 与 0.0.0.0/:: 不报。
fn reportable(src: IpAddr, dst: IpAddr) -> bool {
    !src.is_loopback() && !dst.is_loopback() && !src.is_unspecified() && !dst.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reportable_filters_noise() {
        let lan: IpAddr = "192.168.1.7".parse().unwrap();
        let web: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(reportable(lan, web), "普通出站应上报");
        assert!(!reportable("127.0.0.1".parse().unwrap(), web));
        assert!(!reportable(lan, "127.0.0.1".parse().unwrap()));
        assert!(!reportable(lan, "0.0.0.0".parse().unwrap()));
        assert!(!reportable("::".parse().unwrap(), web));
        assert!(!reportable(lan, "::1".parse().unwrap()));
    }

    #[test]
    fn ports_are_network_byte_order() {
        // 实机勘定：连接 80 端口时原始字段值是 20480
        assert_eq!(u16::from_be(20480), 80);
        assert_eq!(u16::from_be(47873), 443);
    }
}
