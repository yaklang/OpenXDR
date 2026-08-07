//! Windows ETW 采集：Microsoft-Windows-Kernel-Process provider，进程启动事件。
//! 需要管理员权限；失败回落轮询。

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use super::{poll, process_event, EventSink, ProcessRegistry};

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const EVENT_PROCESS_START: u16 = 1;

pub async fn run(agent_id: String, tx: EventSink) {
    let cb_agent_id = agent_id.clone();
    let cb_tx = tx.clone();
    // ETW 回调是 Fn，注册表用 Mutex 包起来共享
    let registry = std::sync::Mutex::new(ProcessRegistry::default());

    let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != EVENT_PROCESS_START {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
            let ppid: Option<u32> = parser.try_parse("ParentProcessID").ok();
            let image: String = parser.try_parse("ImageName").unwrap_or_default();
            let name = image.rsplit('\\').next().unwrap_or(&image).to_string();

            let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
            cb_tx.send(process_event(
                &cb_agent_id,
                &mut reg,
                pid,
                &name,
                Some(&image),
                None, // Kernel-Process provider 不带命令行
                ppid,
                String::new(),
            ));
        })
        .build();

    match UserTrace::new().enable(provider).start_and_process() {
        Ok(_trace) => {
            // trace 句柄保活；channel 关闭即 agent 退出，无需额外清理
            std::future::pending::<()>().await
        }
        Err(e) => {
            eprintln!("ETW 采集不可用（{e:?}），回落到轮询采集");
            poll::run(agent_id, tx).await;
        }
    }
}
