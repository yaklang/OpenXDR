fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("../proto/agent.proto")?;
    println!("cargo:rerun-if-changed=../proto/agent.proto");

    // eBPF 字节码只在 Linux 目标下构建；Windows 走 ETW，不需要
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
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
    }
    Ok(())
}
