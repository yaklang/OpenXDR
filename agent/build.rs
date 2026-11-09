fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 用随 crate 分发的 protoc，构建机不需要另外装
    // SAFETY: build script 是单线程的，此时没有其他线程读环境变量
    unsafe { std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?) };
    tonic_prost_build::compile_protos("../proto/agent.proto")?;
    println!("cargo:rerun-if-changed=../proto/agent.proto");
    // 发布公钥在编译时嵌入（见 upgrade.rs），换了要重新编译
    println!("cargo:rerun-if-env-changed=OPENXDR_RELEASE_PUBKEY");
    build_execblock()?;
    build_ebpf()
}

/// eBPF 字节码需要 nightly 工具链和 bpf-linker，默认不编译。
/// 关掉它 agent 依然可用，只是回落到轮询采集。
#[cfg(feature = "ebpf")]
fn build_ebpf() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }
    let ebpf_dir = format!("{}/ebpf", env!("CARGO_MANIFEST_DIR"));
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "openxdr-agent-ebpf",
            root_dir: &ebpf_dir,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .map_err(|e| format!("eBPF 构建失败: {e}"))?;
    println!("cargo:rerun-if-changed=ebpf/src");
    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn build_ebpf() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(feature = "execblock")]
fn build_execblock() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }
    println!("cargo:rerun-if-changed=lsm/execblock.bpf.c");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    let clang = std::env::var("BPF_CLANG").unwrap_or_else(|_| "clang".into());
    let target = match std::env::var("CARGO_CFG_TARGET_ENDIAN")?.as_str() {
        "little" => "bpfel",
        "big" => "bpfeb",
        other => return Err(format!("未知目标字节序：{other}").into()),
    };
    let output = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("execblock.bpf.o");
    let status = std::process::Command::new(clang)
        .args([
            "-target",
            target,
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            "lsm/execblock.bpf.c",
            "-o",
        ])
        .arg(output)
        .status()?;
    if !status.success() {
        return Err("BPF LSM 构建失败，需要支持 BPF target 的 clang".into());
    }
    Ok(())
}

#[cfg(not(feature = "execblock"))]
fn build_execblock() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
