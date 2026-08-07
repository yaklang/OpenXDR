//! Windows 主机隔离：用防火墙规则封锁进出流量，只放行 server 通道。
//! 规则统一打上 openxdr 前缀，解除时按名字批量删除，不动主机原有规则。

use std::process::Command as Proc;

use super::Outcome;
use crate::pb::Command;

const RULE_PREFIX: &str = "OpenXDR-Isolation";

pub fn isolate(cmd: &Command) -> Outcome {
    if cmd.allow_endpoints.is_empty() {
        return Outcome::failed("拒绝执行：未指定放行地址，隔离后将无法接收解除指令");
    }
    if cmd.dry_run {
        return Outcome::ok(format!(
            "dry-run：将封锁本机进出流量，仅放行 {}",
            cmd.allow_endpoints.join(", ")
        ));
    }

    // 放行规则要先于封锁规则建立，避免中间出现完全断网的窗口
    for (i, ep) in cmd.allow_endpoints.iter().enumerate() {
        let (host, port) = split_endpoint(ep);
        for dir in ["in", "out"] {
            let mut args = vec![
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={RULE_PREFIX}-Allow-{i}-{dir}"),
                format!("dir={dir}"),
                "action=allow".into(),
                format!("remoteip={host}"),
            ];
            if let Some(p) = port {
                args.push("protocol=TCP".into());
                args.push(format!("remoteport={p}"));
            }
            if let Err(e) = netsh(&args) {
                return Outcome::failed(format!("创建放行规则失败: {e}"));
            }
        }
    }

    for dir in ["in", "out"] {
        let args = [
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={RULE_PREFIX}-Block-{dir}"),
            format!("dir={dir}"),
            "action=block".into(),
        ];
        if let Err(e) = netsh(&args) {
            return Outcome::failed(format!("创建封锁规则失败: {e}"));
        }
    }

    Outcome::ok(format!(
        "已隔离本机，放行 {}",
        cmd.allow_endpoints.join(", ")
    ))
}

pub fn unisolate(cmd: &Command) -> Outcome {
    if cmd.dry_run {
        return Outcome::ok(format!("dry-run：将删除所有 {RULE_PREFIX}-* 防火墙规则"));
    }
    // netsh 不支持按前缀批量删，逐条删除已知名字；不存在的规则报错可忽略
    let mut removed = 0;
    for dir in ["in", "out"] {
        if netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            format!("name={RULE_PREFIX}-Block-{dir}"),
        ])
        .is_ok()
        {
            removed += 1;
        }
        for i in 0..16 {
            if netsh(&[
                "advfirewall".into(),
                "firewall".into(),
                "delete".into(),
                "rule".into(),
                format!("name={RULE_PREFIX}-Allow-{i}-{dir}"),
            ])
            .is_ok()
            {
                removed += 1;
            }
        }
    }
    if removed == 0 {
        return Outcome::ok("本机当前未处于隔离状态");
    }
    Outcome::ok(format!("已解除隔离，删除 {removed} 条规则"))
}

fn split_endpoint(ep: &str) -> (&str, Option<&str>) {
    if let Some(rest) = ep.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        return (host, tail.strip_prefix(':'));
    }
    match ep.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        _ => (ep, None),
    }
}

fn netsh(args: &[String]) -> Result<(), String> {
    let out = Proc::new("netsh")
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 netsh（隔离需要管理员权限）: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    Ok(())
}
