use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;

// 生成代码不归我们管，新版 clippy 对 tonic 的 async_trait 展开报 double_must_use
#[allow(clippy::double_must_use)]
pub mod pb {
    tonic::include_proto!("openxdr.agent.v1");
}

// 全 crate 的 eprintln! 走统一日志出口（见 log.rs）：同名宏按文本作用域盖住 std 的，调用点不用改。
// 必须定义在所有 mod 之前，后面声明的模块才看得见
macro_rules! eprintln {
    ($($arg:tt)*) => {
        $crate::log::line(format_args!($($arg)*))
    };
}

mod collector;
mod delivery;
mod enroll;
mod health;
mod log;
mod process_identity;
mod receipts;
mod respond;
mod spool;
mod tls;
mod upgrade;

use pb::agent_service_client::AgentServiceClient;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["version"] => println!("{}", env!("CARGO_PKG_VERSION")),
        ["enroll-request", dir] => match enroll::request(dir.as_ref()) {
            Ok(json) => println!("{json}"),
            Err(e) => exit(&format!("生成接入请求失败：{e}")),
        },
        ["enroll-apply", dir] => {
            if let Err(e) = enroll::apply(dir.as_ref(), std::io::stdin()) {
                exit(&format!("写入接入配置失败：{e}"));
            }
        }
        _ => {
            #[cfg(windows)]
            log::to_file();
            eprintln!(
                "openxdr-agent {} 启动，程序哈希 {}",
                env!("CARGO_PKG_VERSION"),
                upgrade::self_sha256().get(..12).unwrap_or("未知")
            );
            enroll::load_env_file(&enroll::default_env_file());
            agent();
        }
    }
}

fn exit(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

#[tokio::main]
async fn agent() {
    let server = std::env::var("OPENXDR_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8081".into());

    let queue = delivery::open(&server, health::Health::new())
        .unwrap_or_else(|err| exit(&format!("无法打开事件缓存：{err}")));
    let cached = delivery::access(&queue, |spool| spool.session())
        .await
        .unwrap_or_else(|err| exit(&format!("无法恢复注册身份：{err}")));
    let mut identity = cached.as_ref().map(|session| session.agent_id.clone());
    let mut collector_task = cached.map(|session| start_collection(&queue, session));
    let stopping = stop_signal();
    tokio::pin!(stopping);
    loop {
        refresh_collection(&queue, &mut collector_task).await;
        let registration = tokio::select! {
            result = register(&server) => result,
            _ = &mut stopping => {
                finish(&queue, collector_task.take(), None, 0).await;
            }
        };
        match registration {
            Ok((mut client, session)) => {
                eprintln!(
                    "已注册：{}{}",
                    session.agent_id,
                    if session.upgrade_sha256.is_empty() {
                        ""
                    } else {
                        "，分发版本不同，开始自动升级"
                    }
                );
                if identity.as_ref().is_some_and(|id| id != &session.agent_id) {
                    // 旧身份的缓存移进隔离区后退出一次，由服务管理器以新身份拉起，不陷入重启循环
                    let retired = delivery::access(&queue, |spool| spool.retire_identity()).await;
                    exit(&format!(
                        "服务端注册身份已变化（{} → {}），旧身份缓存移入隔离区：{retired:?}；重启后以新身份运行",
                        identity.as_deref().unwrap_or_default(),
                        session.agent_id
                    ));
                }
                if identity.is_none() {
                    let snapshot = session.clone();
                    delivery::access(&queue, move |spool| spool.save_session(&snapshot))
                        .await
                        .unwrap_or_else(|err| exit(&format!("无法保存注册身份：{err}")));
                    identity = Some(session.agent_id.clone());
                    collector_task = Some(start_collection(&queue, session.clone()));
                }
                if !session.upgrade_sha256.is_empty() {
                    let result = tokio::select! {
                        result = tokio::time::timeout(Duration::from_secs(120), upgrade::apply(
                            &mut client, &session.upgrade_platform, &session.upgrade_sha256,
                        )) => Some(result),
                        _ = &mut stopping => None,
                    };
                    match result {
                        Some(Ok(Ok(()))) => {
                            finish(
                                &queue,
                                collector_task.take(),
                                Some((client, session.agent_id.clone())),
                                upgrade::EXIT_UPGRADED,
                            )
                            .await
                        }
                        Some(Ok(Err(err))) => eprintln!("自动升级失败，继续运行当前版本：{err}"),
                        Some(Err(err)) => eprintln!("自动升级下载超时，继续运行当前版本：{err}"),
                        None => {
                            finish(
                                &queue,
                                collector_task.take(),
                                Some((client, session.agent_id.clone())),
                                0,
                            )
                            .await
                        }
                    }
                }
                let mut commands = tokio::spawn(command_loop(
                    client.clone(),
                    session.agent_id.clone(),
                    session.config_json.clone(),
                    queue.clone(),
                ));
                let reporting = tokio::spawn(health::report(
                    client.clone(),
                    session.agent_id.clone(),
                    queue.health.clone(),
                ));
                let collection = collector_task.as_mut().expect("已注册采集任务");
                if collection.config != session.config_json || collection.next.is_some() {
                    collection.next = Some(session.clone());
                    if let Some(stop) = collection.stop.take() {
                        let _ = stop.send(());
                    }
                }
                let stop_requested = {
                    let transfer = delivery::upload(&queue, &mut client, &session.agent_id);
                    tokio::pin!(transfer);
                    loop {
                        tokio::select! {
                            _ = &mut stopping => break true,
                            result = &mut transfer => {
                                if let Err(err) = result { eprintln!("事件补传中断，缓存保留：{err}"); }
                                break false;
                            }
                            // 会话要换（见 command_loop）：未确认的批次留在缓存里，重新注册后补传
                            _ = &mut commands => break false,
                            _ = tokio::time::sleep(Duration::from_millis(250)) => refresh_collection(&queue, &mut collector_task).await,
                        }
                    }
                };
                commands.abort();
                reporting.abort();
                if stop_requested {
                    finish(
                        &queue,
                        collector_task.take(),
                        Some((client, session.agent_id.clone())),
                        0,
                    )
                    .await;
                }
            }
            Err(err) => eprintln!("连接失败，采集缓存继续，5 秒后重试：{err}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
            _ = &mut stopping => finish(&queue, collector_task.take(), None, 0).await,
        }
    }
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())
            .unwrap_or_else(|err| exit(&format!("无法监听停止信号：{err}")));
        let mut interrupt = signal(SignalKind::interrupt())
            .unwrap_or_else(|err| exit(&format!("无法监听中断信号：{err}")));
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
    }
    #[cfg(windows)]
    {
        let mut interrupt = tokio::signal::windows::ctrl_c()
            .unwrap_or_else(|err| exit(&format!("无法监听中断信号：{err}")));
        let mut terminate = tokio::signal::windows::ctrl_break()
            .unwrap_or_else(|err| exit(&format!("无法监听停止信号：{err}")));
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
    }
}

async fn finish(
    queue: &delivery::Queue,
    collection: Option<Collection>,
    connection: Option<(AgentServiceClient<tonic::transport::Channel>, String)>,
    code: i32,
) -> ! {
    let transfer = async {
        if let Some((mut client, identity)) = connection
            && let Err(err) = delivery::upload(queue, &mut client, &identity).await
        {
            eprintln!("停止期间补传中断，已落盘批次保留：{err}");
        }
        std::future::pending::<()>().await;
    };
    let result = tokio::select! {
        result = drain_collection(collection, Duration::from_secs(30)) => result,
        _ = transfer => unreachable!(),
    };
    match result {
        Ok(()) => {
            eprintln!("采集入口已关闭，已接收事件落盘完成；未确认批次留待下次补传。退出码 {code}");
            std::process::exit(code);
        }
        Err(err) => exit(&format!(
            "停止排空失败，已落盘批次保留，内存中事件可能丢失：{err}"
        )),
    }
}

async fn drain_collection(
    collection: Option<Collection>,
    timeout: Duration,
) -> std::io::Result<()> {
    let Some(mut collection) = collection else {
        return Ok(());
    };
    if let Some(stop) = collection.stop.take() {
        let _ = stop.send(());
    }
    // 丢弃 next，停止进程时不再启动配置切换后的采集器。
    let result = tokio::time::timeout(timeout, &mut collection.task).await;
    match result {
        Ok(result) => result.map_err(std::io::Error::other)?,
        Err(_) => {
            collection.task.abort();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "等待事件落盘超时",
            ))
        }
    }
}

struct Collection {
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    config: String,
    next: Option<pb::RegisterResponse>,
}

async fn refresh_collection(queue: &delivery::Queue, collection: &mut Option<Collection>) {
    if !collection
        .as_ref()
        .is_some_and(|value| value.task.is_finished())
    {
        return;
    }
    let previous = collection.take().expect("已检查采集任务");
    match previous.task.await {
        Ok(Ok(())) if previous.next.is_some() => {
            let session = previous.next.expect("已确认配置切换");
            let snapshot = session.clone();
            delivery::access(queue, move |spool| spool.save_session(&snapshot))
                .await
                .unwrap_or_else(|err| exit(&format!("保存采集配置失败：{err}")));
            *collection = Some(start_collection(queue, session));
        }
        result => exit(&format!("事件持久化任务退出：{result:?}")),
    }
}

fn start_collection(queue: &delivery::Queue, session: pb::RegisterResponse) -> Collection {
    let events = collector::spawn(
        session.agent_id,
        collector::Config::parse(&session.config_json),
        queue.health.clone(),
    );
    let (stop, stopping) = tokio::sync::oneshot::channel();
    Collection {
        task: tokio::spawn(delivery::collect(queue.clone(), events, stopping)),
        stop: Some(stop),
        config: session.config_json,
        next: None,
    }
}

async fn register(
    server: &str,
) -> Result<
    (
        AgentServiceClient<tonic::transport::Channel>,
        pb::RegisterResponse,
    ),
    Box<dyn std::error::Error>,
> {
    let channel = tokio::time::timeout(Duration::from_secs(15), tls::connect(server)).await??;
    let mut client = AgentServiceClient::new(channel);

    let resp = tokio::time::timeout(Duration::from_secs(30), client.register(register_request()))
        .await??
        .into_inner();
    Ok((client, resp))
}

fn register_request() -> pb::RegisterRequest {
    pb::RegisterRequest {
        hostname: enroll::hostname(),
        os: std::env::consts::OS.into(),
        ip_addrs: local_ips(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        arch: std::env::consts::ARCH.into(),
        binary_sha256: upgrade::self_sha256().into(),
    }
}

/// 常驻指令通道：先发一条带 agent_id 的空结果认领连接，
/// 之后逐条执行 server 推来的指令并回执。
/// 指令通道断开时自己重连，不牵动事件补传。断开多半是 server 重启：重连前重报一次注册，
/// 分发版本、采集配置或注册身份变了就结束本次会话，由主循环重新注册后升级或换配置——
/// 否则 server 重启后只有指令通道在重连，新版本推不下去（生产上有 6 台一直没升上去）。
async fn command_loop(
    client: AgentServiceClient<tonic::transport::Channel>,
    agent_id: String,
    config: String,
    queue: delivery::Queue,
) {
    let receiving = async {
        loop {
            command_stream(client.clone(), agent_id.clone(), queue.clone()).await;
            eprintln!("指令通道断开，5 秒后重连");
            tokio::time::sleep(Duration::from_secs(5)).await;
            if session_changed(client.clone(), &agent_id, &config).await {
                eprintln!("分发版本、采集配置或注册身份已变，重新注册");
                return;
            }
        }
    };
    tokio::select! {
        _ = receiving => {}
        _ = receipts::upload(client.clone(), queue.clone(), agent_id.clone()) => {}
    }
}

/// 重报注册看会话是否要换。注册失败按没变处理：照旧重连指令通道，事件补传自有重试
async fn session_changed(
    mut client: AgentServiceClient<tonic::transport::Channel>,
    agent_id: &str,
    config: &str,
) -> bool {
    match tokio::time::timeout(Duration::from_secs(30), client.register(register_request())).await {
        Ok(Ok(resp)) => {
            let resp = resp.into_inner();
            !resp.upgrade_sha256.is_empty()
                || resp.config_json != config
                || resp.agent_id != agent_id
        }
        _ => false,
    }
}

async fn command_stream(
    mut client: AgentServiceClient<tonic::transport::Channel>,
    agent_id: String,
    queue: delivery::Queue,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    // 认领消息：只带 agent_id，command_id 为空
    if tx
        .send(pb::CommandResult {
            agent_id: agent_id.clone(),
            ..Default::default()
        })
        .await
        .is_err()
    {
        return;
    }

    let mut inbound = match client.commands(ReceiverStream::new(rx)).await {
        Ok(stream) => stream.into_inner(),
        Err(e) => {
            eprintln!("指令通道建立失败: {e}");
            return;
        }
    };

    while let Ok(Some(cmd)) = inbound.message().await {
        // exec 可能跑很久，并发执行；结束进程与隔离保持顺序，先隔离后解除不能颠倒
        if cmd.kind() == pb::CommandKind::Exec {
            tokio::spawn(run_command(
                agent_id.clone(),
                cmd,
                queue.clone(),
                tx.clone(),
            ));
        } else if !run_command(agent_id.clone(), cmd, queue.clone(), tx.clone()).await {
            return;
        }
    }
}

/// 先持久记录执行占位；断线不取消执行，结果独立重传。
/// 结果同时顺着指令流回一份：没有独立回执接口的旧 server 只认这条路，新 server 重复收到按终态幂等
async fn run_command(
    agent_id: String,
    cmd: pb::Command,
    queue: delivery::Queue,
    stream: tokio::sync::mpsc::Sender<pb::CommandResult>,
) -> bool {
    let id = agent_id.clone();
    let command = cmd.id.clone();
    match delivery::access(&queue, move |s| s.receipts.reserve(&id, &command)).await {
        Ok(true) => (),
        Ok(false) => {
            eprintln!("指令已有执行记录，不重复执行: {}", cmd.id);
            return true;
        }
        Err(error) => {
            eprintln!("无法持久预留回执，拒绝执行: {error}");
            return false;
        }
    }
    let result = respond::execute(&agent_id, &cmd).await;
    eprintln!("执行指令 {}: {}", cmd.id, result.detail);
    loop {
        let retained = result.clone();
        match delivery::access(&queue, move |s| s.receipts.finish(retained)).await {
            Ok(()) => {
                let _ = stream.send(result).await;
                return true;
            }
            Err(error) => eprintln!("回执落盘失败，保留内存结果等待重写，不重执行: {error}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// 本机非回环 IP。server 按这些地址把探针看到的网络流量归属到本资产，
/// 端点侧和流量侧的证据才能落到同一实体上。
fn local_ips() -> Vec<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.addr.ip().to_string())
        .collect()
}

#[cfg(test)]
mod command_tests {
    use super::*;
    use pb::agent_service_server::{AgentService, AgentServiceServer};
    use tonic::{Request, Response, Status, Streaming};

    struct Server {
        seen: tokio::sync::mpsc::Sender<()>,
        results: std::sync::Arc<std::sync::Mutex<Vec<pb::CommandResult>>>,
        mode: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        /// 注册时下发的分发版本哈希；None 表示注册接口不可用
        upgrade: Option<String>,
    }
    #[tonic::async_trait]
    impl AgentService for Server {
        async fn report_command_result(
            &self,
            request: Request<pb::CommandResult>,
        ) -> Result<Response<pb::CommandResultAck>, Status> {
            let result = request.into_inner();
            self.results.lock().unwrap().push(result.clone());
            match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
                0 => Err(Status::unimplemented("旧服务端")),
                1 => Err(Status::unavailable("模拟持久接收后丢失 ACK")),
                2 => Ok(Response::new(pb::CommandResultAck {
                    command_id: uuid::Uuid::new_v4().to_string(),
                })),
                _ => Ok(Response::new(pb::CommandResultAck {
                    command_id: result.command_id,
                })),
            }
        }

        async fn report_health(
            &self,
            _: Request<pb::HealthRequest>,
        ) -> Result<Response<pb::HealthAck>, Status> {
            Err(Status::unimplemented("测试不使用状态通道"))
        }
        async fn register(
            &self,
            _: Request<pb::RegisterRequest>,
        ) -> Result<Response<pb::RegisterResponse>, Status> {
            match &self.upgrade {
                Some(sha) => Ok(Response::new(pb::RegisterResponse {
                    agent_id: "reconnect-test".into(),
                    upgrade_sha256: sha.clone(),
                    ..Default::default()
                })),
                None => Err(Status::unimplemented("测试只使用指令流")),
            }
        }
        async fn report_events(
            &self,
            _: Request<Streaming<pb::AgentEvent>>,
        ) -> Result<Response<pb::ReportAck>, Status> {
            Err(Status::unimplemented("测试不启动事件上报"))
        }
        type DownloadAgentStream =
            tokio_stream::Iter<std::vec::IntoIter<Result<pb::AgentChunk, Status>>>;
        async fn download_agent(
            &self,
            _: Request<pb::DownloadRequest>,
        ) -> Result<Response<Self::DownloadAgentStream>, Status> {
            Err(Status::unimplemented("测试不下载安装包"))
        }
        type CommandsStream = tokio_stream::Iter<std::vec::IntoIter<Result<pb::Command, Status>>>;
        async fn commands(
            &self,
            request: Request<Streaming<pb::CommandResult>>,
        ) -> Result<Response<Self::CommandsStream>, Status> {
            let first = request.into_inner().message().await?.unwrap();
            assert_eq!(first.agent_id, "reconnect-test");
            self.seen.send(()).await.unwrap();
            // 正常关闭指令流，不断开 HTTP/2 连接。
            Ok(Response::new(tokio_stream::iter(Vec::new())))
        }
    }
    #[tokio::test]
    async fn receipt_replays_after_lost_ack_and_restart() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connections, incoming) = tokio::sync::mpsc::channel(4);
        let accept = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                if connections
                    .send(Ok::<_, std::io::Error>(socket))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let (seen, _) = tokio::sync::mpsc::channel(4);
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mode = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(Server {
                    seen,
                    upgrade: None,
                    results: results.clone(),
                    mode: mode.clone(),
                }))
                .serve_with_incoming(ReceiverStream::new(incoming)),
        );
        let mut client = AgentServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(format!("receipt-rpc-test-{}", uuid::Uuid::new_v4()));
        let agent = uuid::Uuid::new_v4().to_string();
        let command = pb::Command {
            id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let queue = delivery::Queue::new(
            spool::Spool::open(&dir, 4 * 1024 * 1024).unwrap(),
            health::Health::new(),
        );
        // 未指定动作会产生明确失败回执，不触碰系统；重复投递也不能覆盖首次结果。
        let (stream, mut streamed) = tokio::sync::mpsc::channel(4);
        assert!(
            run_command(
                agent.clone(),
                command.clone(),
                queue.clone(),
                stream.clone()
            )
            .await
        );
        assert!(
            run_command(
                agent.clone(),
                command.clone(),
                queue.clone(),
                stream.clone()
            )
            .await
        );
        // 结果顺着指令流回过一份，重复投递不再回
        assert_eq!(streamed.recv().await.unwrap().command_id, command.id);
        assert!(streamed.try_recv().is_err());
        mode.store(1, std::sync::atomic::Ordering::SeqCst);
        assert!(
            receipts::upload_once(&mut client, &queue, &agent)
                .await
                .is_err()
        );
        drop(queue);
        let queue = delivery::Queue::new(
            spool::Spool::open(&dir, 4 * 1024 * 1024).unwrap(),
            health::Health::new(),
        );
        mode.store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(
            receipts::upload_once(&mut client, &queue, &agent)
                .await
                .is_err()
        );
        mode.store(3, std::sync::atomic::Ordering::SeqCst);
        receipts::upload_once(&mut client, &queue, &agent)
            .await
            .unwrap();
        receipts::upload_once(&mut client, &queue, &agent)
            .await
            .unwrap();
        {
            let received = results.lock().unwrap();
            assert_eq!(received.len(), 3);
            assert!(received.iter().all(|r| r == &received[0]));
        }

        // 旧 server 没有独立回执接口：结果已走指令流，本地记录确认掉，不无限重传
        let old = pb::Command {
            id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        };
        assert!(run_command(agent.clone(), old, queue.clone(), stream).await);
        mode.store(0, std::sync::atomic::Ordering::SeqCst);
        receipts::upload_once(&mut client, &queue, &agent)
            .await
            .unwrap();
        let left = delivery::access(&queue, {
            let agent = agent.clone();
            move |s| s.receipts.pending(&agent)
        })
        .await
        .unwrap();
        assert!(left.is_empty());
        drop(queue);
        server.abort();
        accept.abort();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// 起一个只认指令流的模拟服务端，返回客户端、每次建立指令流的通知与要收尾的任务
    async fn command_server(
        upgrade: Option<String>,
    ) -> (
        AgentServiceClient<tonic::transport::Channel>,
        tokio::sync::mpsc::Receiver<()>,
        [tokio::task::JoinHandle<()>; 2],
    ) {
        // 注册请求带自身哈希：第一次算要同步读整个测试二进制（arm64 上几百 MB），先算好，不占用例的时限
        tokio::task::spawn_blocking(upgrade::self_sha256)
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connections, incoming) = tokio::sync::mpsc::channel(4);
        let accept = tokio::spawn(async move {
            loop {
                let socket = listener.accept().await.map(|(s, _)| s);
                if connections.send(socket).await.is_err() {
                    return;
                }
            }
        });
        let (seen, calls) = tokio::sync::mpsc::channel(4);
        let server = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(Server {
                    seen,
                    results: Default::default(),
                    mode: Default::default(),
                    upgrade,
                }))
                .serve_with_incoming(ReceiverStream::new(incoming))
                .await;
        });
        let client = AgentServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        (client, calls, [server, accept])
    }

    fn test_queue() -> (std::path::PathBuf, delivery::Queue) {
        let dir = std::env::temp_dir().join(format!("command-test-{}", uuid::Uuid::new_v4()));
        let queue = delivery::Queue::new(
            spool::Spool::open(&dir, 4 * 1024 * 1024).unwrap(),
            health::Health::new(),
        );
        (dir, queue)
    }

    #[tokio::test]
    async fn command_stream_reconnects_without_event_stream_restart() {
        let (client, mut calls, tasks) = command_server(None).await;
        let (dir, queue) = test_queue();
        let commands = tokio::spawn(command_loop(
            client,
            "reconnect-test".into(),
            String::new(),
            queue,
        ));
        let result = tokio::time::timeout(Duration::from_secs(8), async {
            assert!(calls.recv().await.is_some());
            assert!(calls.recv().await.is_some());
        })
        .await;
        commands.abort();
        tasks.iter().for_each(|t| t.abort());
        let _ = commands.await;
        std::fs::remove_dir_all(dir).unwrap();
        result.unwrap();
    }

    /// 指令通道断开后重报注册发现分发版本变了：结束会话交给主循环重新注册升级，不再只重连指令通道
    #[tokio::test]
    async fn command_loop_ends_session_when_upgrade_is_pending() {
        let (client, mut calls, tasks) = command_server(Some("new-build".into())).await;
        let (dir, queue) = test_queue();
        let commands = tokio::spawn(command_loop(
            client,
            "reconnect-test".into(),
            String::new(),
            queue,
        ));
        assert!(calls.recv().await.is_some(), "先建立一次指令流");
        let ended = tokio::time::timeout(Duration::from_secs(10), commands).await;
        tasks.iter().for_each(|t| t.abort());
        std::fs::remove_dir_all(dir).unwrap();
        assert!(ended.is_ok(), "有待升级时指令通道断开应结束会话");
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "由 sigterm_reaches_shutdown_listener 启动的隔离子进程"]
    async fn signal_listener_child() {
        let ready = std::env::var_os("OPENXDR_TEST_SIGNAL_READY").expect("仅由父测试调用");
        let stopping = stop_signal();
        tokio::pin!(stopping);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut stopping)
                .await
                .is_err()
        );
        std::fs::write(ready, "ready").unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut stopping)
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_reaches_shutdown_listener() {
        let ready = std::env::temp_dir().join(format!("openxdr-signal-{}", uuid::Uuid::new_v4()));
        let child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shutdown_tests::signal_listener_child",
                "--ignored",
            ])
            .env("OPENXDR_TEST_SIGNAL_READY", &ready)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            // SAFETY: 纯 FFI 调用，只传 pid 与信号编号；子进程尚未被 wait 回收，pid 不会被复用到别的进程上。
            unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) },
            0
        );
        let result = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        std::fs::remove_file(ready).unwrap();
        assert!(result.status.success(), "{:?}", result);
    }

    #[tokio::test]
    async fn failed_writer_is_not_reported_as_flushed() {
        let task = tokio::spawn(async { Err(std::io::Error::other("模拟磁盘故障")) });
        let error = drain_collection(
            Some(Collection {
                task,
                stop: None,
                config: String::new(),
                next: None,
            }),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("模拟磁盘故障"));
    }

    #[tokio::test]
    async fn blocked_writer_times_out_and_is_aborted() {
        let (dropped, received) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _dropped = dropped;
            std::future::pending::<std::io::Result<()>>().await
        });
        let error = drain_collection(
            Some(Collection {
                task,
                stop: None,
                config: String::new(),
                next: None,
            }),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), received)
                .await
                .unwrap()
                .is_err()
        );
    }
}
