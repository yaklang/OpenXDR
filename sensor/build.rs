fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 用随 crate 分发的 protoc，构建机不需要另外装
    // SAFETY: build script 是单线程的，此时没有其他线程读环境变量
    unsafe { std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?) };
    tonic_prost_build::compile_protos("../proto/sensor.proto")?;
    println!("cargo:rerun-if-changed=../proto/sensor.proto");
    build_xdp()
}

/// XDP 重定向程序需要 nightly 工具链和 bpf-linker，默认不编译。
/// 关掉它探针依然可用，只是没有 afxdp 后端，走默认的 AF_PACKET。
#[cfg(feature = "xdp")]
fn build_xdp() -> Result<(), Box<dyn std::error::Error>> {
    let ebpf_dir = format!("{}/ebpf", env!("CARGO_MANIFEST_DIR"));
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "openxdr-sensor-ebpf",
            root_dir: &ebpf_dir,
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
    .map_err(|e| format!("XDP 程序构建失败: {e}"))?;
    println!("cargo:rerun-if-changed=ebpf/src");
    Ok(())
}

#[cfg(not(feature = "xdp"))]
fn build_xdp() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
