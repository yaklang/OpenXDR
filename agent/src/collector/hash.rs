//! 可执行文件哈希。进程事件带上 exe 的 SHA-256，服务端才能与哈希情报碰撞。
//!
//! 同一 (路径, mtime, 大小) 只算一次：系统里活跃的可执行文件是有限集合，
//! 进程风暴（编译、脚本批跑）反复启动的是同一批二进制，缓存命中是常态。

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

/// 超过此大小不算哈希，避免罕见的巨型二进制卡住采集线程
const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;
/// 缓存条目上限，防御路径爆炸；满了整体清空，代价只是重算一轮
const MAX_ENTRIES: usize = 4096;

static CACHE: LazyLock<Mutex<HashMap<(String, SystemTime, u64), String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 计算可执行文件的 SHA-256（十六进制小写）。文件不可读或过大时返回 None。
pub fn exe_sha256(path: &str) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_SIZE {
        return None;
    }
    let key = (path.to_string(), meta.modified().ok()?, meta.len());
    if let Some(hit) = CACHE.lock().unwrap().get(&key) {
        return Some(hit.clone());
    }

    let mut hasher = Sha256::new();
    io::copy(&mut File::open(path).ok()?, &mut hasher).ok()?;
    let digest = format!("{:x}", hasher.finalize());

    let mut cache = CACHE.lock().unwrap();
    if cache.len() >= MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(key, digest.clone());
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hashes_known_content() {
        let dir = std::env::temp_dir();
        let path = dir.join("openxdr_hash_test.bin");
        File::create(&path).unwrap().write_all(b"abc").unwrap();
        let got = exe_sha256(path.to_str().unwrap()).unwrap();
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 第二次走缓存，结果一致
        assert_eq!(exe_sha256(path.to_str().unwrap()).unwrap(), got);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_none() {
        assert!(exe_sha256("/nonexistent/openxdr").is_none());
    }
}
