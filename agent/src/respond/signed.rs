//! 指令签名信封：只执行 server 指令签名私钥签过、签给本机且未过期的指令。
//!
//! 指令通道之外的任何一环（数据库、跨节点 NATS、单个投递节点）被人摸到，
//! 都签不出本机认的指令。验签对象是信封原始字节，外层明文字段一律不采信。

use prost::Message;
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::pb::{Command, SignedCommand};

/// 签名域前缀，与 server 侧一致
const CONTEXT: &[u8] = b"openxdr-command-v1\0";

pub fn open(
    cmd: &Command,
    signer: Option<&[u8]>,
    agent_id: &str,
    now_unix: i64,
) -> Result<Command, String> {
    let signer = signer.ok_or("本机未固定指令签名公钥（server 未配置签名或版本过旧）")?;
    let message = [CONTEXT, &cmd.envelope].concat();
    UnparsedPublicKey::new(&ED25519, signer)
        .verify(&message, &cmd.signature)
        .map_err(|_| "指令签名校验失败".to_string())?;
    let envelope = SignedCommand::decode(cmd.envelope.as_slice())
        .map_err(|err| format!("签名信封无法解析：{err}"))?;
    if envelope.agent_id != agent_id {
        return Err(format!("指令签给 {}，不是本机", envelope.agent_id));
    }
    if now_unix > envelope.expires_unix {
        return Err(format!(
            "指令已于 {} 过期（本机时间 {now_unix}）",
            envelope.expires_unix
        ));
    }
    envelope.command.ok_or_else(|| "签名信封里没有指令".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::CommandKind;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    fn sealed(key: &Ed25519KeyPair, agent: &str, expires: i64) -> Command {
        let inner = Command {
            id: "inner".into(),
            kind: CommandKind::BlockNetwork as i32,
            target: "10.1.1.170".into(),
            ..Default::default()
        };
        let envelope = SignedCommand {
            command: Some(inner),
            agent_id: agent.into(),
            expires_unix: expires,
        }
        .encode_to_vec();
        let signature = key.sign(&[CONTEXT, &envelope].concat()).as_ref().to_vec();
        // 外层明文故意写成别的：agent 只认信封里的
        Command {
            id: "outer".into(),
            kind: CommandKind::Exec as i32,
            cmd: "rm -rf /".into(),
            envelope,
            signature,
            ..Default::default()
        }
    }

    #[test]
    fn executes_only_the_signed_inner_command() {
        let key = key();
        let public = key.public_key().as_ref();
        let inner = open(&sealed(&key, "a1", 100), Some(public), "a1", 50).unwrap();
        assert_eq!(inner.id, "inner");
        assert_eq!(inner.kind(), CommandKind::BlockNetwork);
        assert!(inner.cmd.is_empty());
    }

    #[test]
    fn rejects_forged_rebound_expired_or_unpinned() {
        let key = key();
        let public = key.public_key().as_ref();
        let other = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        assert!(open(&sealed(&other, "a1", 100), Some(public), "a1", 50).is_err());
        assert!(open(&sealed(&key, "a2", 100), Some(public), "a1", 50).is_err());
        assert!(open(&sealed(&key, "a1", 100), Some(public), "a1", 101).is_err());
        assert!(open(&sealed(&key, "a1", 100), None, "a1", 50).is_err());
        let mut tampered = sealed(&key, "a1", 100);
        *tampered.envelope.last_mut().unwrap() ^= 1;
        assert!(open(&tampered, Some(public), "a1", 50).is_err());
        let unsigned = Command {
            kind: CommandKind::Exec as i32,
            cmd: "id".into(),
            ..Default::default()
        };
        assert!(open(&unsigned, Some(public), "a1", 50).is_err());
    }

    /// 与 server 侧 TestSignatureVector 同一组向量：全零种子对 "vector" 的签名
    #[test]
    fn matches_server_signature_vector() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[0; 32]).unwrap();
        let sig = key.sign(&[CONTEXT, b"vector"].concat());
        let hex: String = sig.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "910c37eca5987fa58fd26fc717f63836271fcdd9a8258fdc26d303fba9ae675f\
             3de392bab17596105c3268b2ea48f4b60cac0467ca755b72c30b747693f94f0b"
        );
    }
}
