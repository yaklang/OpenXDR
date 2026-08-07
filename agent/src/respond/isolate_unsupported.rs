//! 非 Linux/Windows 平台没有实现隔离。明确报 unsupported，
//! 而不是假装成功——界面上显示"已隔离"但主机照常通信是最坏的结果。

use super::Outcome;
use crate::pb::Command;

pub fn isolate(_cmd: &Command) -> Outcome {
    Outcome::unsupported("本平台未实现主机隔离")
}

pub fn unisolate(_cmd: &Command) -> Outcome {
    Outcome::unsupported("本平台未实现主机隔离")
}
