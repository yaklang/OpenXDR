//! 采集独立于连接存活；先落盘，再发送有限批次，完整 ACK 后删除。
use std::io;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::{pb, spool::Spool};
use pb::agent_service_client::AgentServiceClient;

#[derive(Clone)]
pub struct Queue {
    spool: Arc<Mutex<Spool>>,
    pub health: Arc<crate::health::Health>,
}
impl Queue {
    pub(crate) fn new(spool: Spool, health: Arc<crate::health::Health>) -> Self {
        health.queue(spool.bytes(), spool.batches(), spool.limit());
        health.receipts(spool.receipts.stats());
        Self {
            spool: Arc::new(Mutex::new(spool)),
            health,
        }
    }
}

/// agent 的状态目录：事件缓存、回执、隔离的文件都放在下面
pub fn state_root() -> PathBuf {
    std::env::var_os("OPENXDR_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            #[cfg(windows)]
            {
                PathBuf::from(
                    std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()),
                )
                .join("OpenXDR")
                .join("state")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("/var/lib/openxdr/agent")
            }
        })
}

pub fn open(server: &str, health: Arc<crate::health::Health>) -> io::Result<Queue> {
    let root = state_root();
    let scope = format!("{}\n{}", server, crate::enroll::hostname());
    let key = format!("{:x}", Sha256::digest(scope.as_bytes()));
    let limit = match std::env::var("OPENXDR_SPOOL_MAX_BYTES") {
        Ok(value) => value
            .parse()
            .map_err(|_| io::Error::other("OPENXDR_SPOOL_MAX_BYTES 无效"))?,
        Err(_) => 256 * 1024 * 1024,
    };
    let spool = Spool::open(&root.join(key), limit)?;
    eprintln!(
        "恢复事件缓存：{} 批，{} 字节",
        spool.batches(),
        spool.bytes()
    );
    Ok(Queue::new(spool, health))
}

pub async fn access<T: Send + 'static>(
    queue: &Queue,
    f: impl FnOnce(&mut Spool) -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let queue = queue.clone();
    tokio::task::spawn_blocking(move || {
        let mut spool = queue
            .spool
            .lock()
            .map_err(|_| io::Error::other("缓存锁已损坏"))?;
        let result = f(&mut spool);
        queue
            .health
            .queue(spool.bytes(), spool.batches(), spool.limit());
        queue.health.receipts(spool.receipts.stats());
        result
    })
    .await
    .map_err(io::Error::other)?
}

pub async fn collect(
    queue: Queue,
    mut events: mpsc::Receiver<pb::AgentEvent>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut batch = Vec::new();
    let mut bytes = 0;
    let mut stopping = false;
    let mut since = tokio::time::Instant::now();
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    loop {
        // 在线时每秒落一批，补传延迟低；有积压（离线）时攒大批再落，
        // 否则每秒一个小文件，文件数上限会远早于字节上限撞满
        let backlog = queue.health.queued_batches() > BACKLOG_BATCHES;
        let (interval, events_max) = match backlog {
            true => (Duration::from_secs(30), 500),
            false => (Duration::from_secs(1), 128),
        };
        let event = tokio::select! {
            event = events.recv() => event,
            _ = &mut stop, if !stopping => { events.close(); stopping = true; continue; }
            _ = timer.tick() => {
                if since.elapsed() >= interval {
                    persist(&queue, &mut batch).await?;
                    (bytes, since) = (0, tokio::time::Instant::now());
                }
                continue;
            }
        };
        let Some(event) = event else {
            return persist(&queue, &mut batch).await;
        };
        let size = event.encoded_len() + 8;
        if size > 3 * 1024 * 1024 {
            // 丢弃并计数：一条异常事件不能让整个 agent 退出
            queue.health.dropped.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "丢弃超过持久批次上限的采集事件（class_uid={}）",
                event.class_uid
            );
            continue;
        }
        if bytes + size > 3 * 1024 * 1024 {
            persist(&queue, &mut batch).await?;
            (bytes, since) = (0, tokio::time::Instant::now());
        }
        bytes += size;
        batch.push(event);
        if batch.len() >= events_max {
            persist(&queue, &mut batch).await?;
            (bytes, since) = (0, tokio::time::Instant::now());
        }
    }
}

/// 缓存里积压超过这么多批，视为补传跟不上（离线或 server 慢），改攒大批
const BACKLOG_BATCHES: u64 = 16;

async fn persist(queue: &Queue, batch: &mut Vec<pb::AgentEvent>) -> io::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    loop {
        let copy = batch.clone();
        match access(queue, move |spool| spool.append(copy)).await {
            Ok(_) => {
                queue
                    .health
                    .write_blocked
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                batch.clear();
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::StorageFull => {
                queue
                    .health
                    .write_blocked
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                eprintln!("事件缓存已满，保留待写批次；采集内存队列可能开始丢失事件");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

pub async fn upload(
    queue: &Queue,
    client: &mut AgentServiceClient<tonic::transport::Channel>,
    agent_id: &str,
) -> io::Result<()> {
    loop {
        let batch = access(queue, |spool| spool.front()).await?;
        let Some(batch) = batch else {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        };
        if batch.events.iter().any(|event| event.agent_id != agent_id) {
            return Err(io::Error::other(
                "缓存身份与当前注册不一致，停止补传，保留原证据",
            ));
        }
        let sequence = batch.sequence;
        // 落盘批次可能有 500 条；逐条持久入队时整批容易超时。分段传输，
        // 所有分段确认后才删落盘批次，失败重放仍保留原事件身份。
        for events in batch.events.chunks(64) {
            let mut request = tonic::Request::new(tokio_stream::iter(events.to_vec()));
            request.set_timeout(Duration::from_secs(30));
            let ack = tokio::time::timeout(Duration::from_secs(35), client.report_events(request))
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?
                .into_inner();
            if ack.received != events.len() as u64 {
                return Err(io::Error::other("分段确认数量不符，保留原批次"));
            }
        }
        let received = batch.events.len() as u64;
        access(queue, move |spool| spool.acknowledge(sequence, received)).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb::agent_service_server::{AgentService, AgentServiceServer};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::{Request, Response, Status, Streaming};

    struct Server {
        short_ack: bool,
        calls: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<Vec<pb::AgentEvent>>>>,
    }
    #[tonic::async_trait]
    impl AgentService for Server {
        async fn report_command_result(
            &self,
            _: Request<pb::CommandResult>,
        ) -> Result<Response<pb::CommandResultAck>, Status> {
            Err(Status::unimplemented("测试不使用独立回执确认"))
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
            Err(Status::unimplemented("仅测试上报"))
        }
        async fn report_events(
            &self,
            request: Request<Streaming<pb::AgentEvent>>,
        ) -> Result<Response<pb::ReportAck>, Status> {
            let mut stream = request.into_inner();
            let mut events = Vec::new();
            while let Some(event) = stream.message().await? {
                events.push(event);
            }
            let count = events.len() as u64;
            self.seen.lock().unwrap().push(events);
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                if self.short_ack {
                    return Ok(Response::new(pb::ReportAck {
                        received: count - 1,
                    }));
                }
                return Err(Status::unavailable("模拟接收成功后 ACK 丢失"));
            }
            Ok(Response::new(pb::ReportAck { received: count }))
        }
        type CommandsStream = tokio_stream::Iter<std::vec::IntoIter<Result<pb::Command, Status>>>;
        async fn commands(
            &self,
            _: Request<Streaming<pb::CommandResult>>,
        ) -> Result<Response<Self::CommandsStream>, Status> {
            Err(Status::unimplemented("仅测试上报"))
        }
        type DownloadAgentStream =
            tokio_stream::Iter<std::vec::IntoIter<Result<pb::AgentChunk, Status>>>;
        async fn download_agent(
            &self,
            _: Request<pb::DownloadRequest>,
        ) -> Result<Response<Self::DownloadAgentStream>, Status> {
            Err(Status::unimplemented("仅测试上报"))
        }
    }

    #[tokio::test]
    async fn offline_shutdown_flushes_accepted_events_before_restart() {
        let dir =
            std::env::temp_dir().join(format!("openxdr-collect-test-{}", uuid::Uuid::new_v4()));
        let queue = Queue::new(
            Spool::open(&dir, 8 << 20).unwrap(),
            crate::health::Health::new(),
        );
        let (tx, rx) = mpsc::channel(4);
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(collect(queue.clone(), rx, stopping));
        let event = pb::AgentEvent {
            agent_id: "identity".into(),
            raw_json: "{}".into(),
            ..Default::default()
        };
        tx.send(event.clone()).await.unwrap();
        tx.send(event.clone()).await.unwrap();
        crate::drain_collection(
            Some(crate::Collection {
                task,
                stop: Some(stop),
                config: String::new(),
                next: Some(pb::RegisterResponse::default()),
            }),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(tx.is_closed());
        drop(queue);
        let queue = Queue::new(
            Spool::open(&dir, 8 << 20).unwrap(),
            crate::health::Health::new(),
        );
        let mut recovered = Vec::new();
        {
            let mut spool = queue.spool.lock().unwrap();
            while let Some(batch) = spool.front().unwrap() {
                let count = batch.events.len() as u64;
                recovered.extend(batch.events);
                spool.acknowledge(batch.sequence, count).unwrap();
            }
        }
        assert_eq!(recovered, vec![event.clone(), event]);
        drop(queue);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn lost_ack_replays_identical_batch_after_restart() {
        replay_after_failed_chunk(false).await;
    }

    #[tokio::test]
    async fn short_chunk_ack_preserves_entire_batch_after_restart() {
        replay_after_failed_chunk(true).await;
    }

    async fn replay_after_failed_chunk(short_ack: bool) {
        let dir =
            std::env::temp_dir().join(format!("openxdr-delivery-test-{}", uuid::Uuid::new_v4()));
        let queue = Queue::new(
            Spool::open(&dir, 8 << 20).unwrap(),
            crate::health::Health::new(),
        );
        let events: Vec<_> = (0..130)
            .map(|i| pb::AgentEvent {
                agent_id: "identity".into(),
                ts_unix_ns: 123456 + i,
                raw_json: "{}".into(),
                ..Default::default()
            })
            .collect();
        queue.spool.lock().unwrap().append(events.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(2);
        let accept = tokio::spawn(async move {
            loop {
                if tx
                    .send(listener.accept().await.map(|(stream, _)| stream))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(Server {
                    short_ack,
                    calls: Arc::new(AtomicUsize::new(0)),
                    seen: seen.clone(),
                }))
                .serve_with_incoming(ReceiverStream::new(rx)),
        );
        let mut client = AgentServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        assert!(upload(&queue, &mut client, "identity").await.is_err());
        assert_eq!(queue.spool.lock().unwrap().batches(), 1);
        drop(queue);
        let queue = Queue::new(
            Spool::open(&dir, 8 << 20).unwrap(),
            crate::health::Health::new(),
        );
        let q = queue.clone();
        let upload = tokio::spawn(async move { upload(&q, &mut client, "identity").await });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if queue.spool.lock().unwrap().batches() == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                events[..64].to_vec(),
                events[64..128].to_vec(),
                events[..64].to_vec(),
                events[64..128].to_vec(),
                events[128..].to_vec(),
            ]
        );
        upload.abort();
        let _ = upload.await;
        server.abort();
        accept.abort();
        drop(queue);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
