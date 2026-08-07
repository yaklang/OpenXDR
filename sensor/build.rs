fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::compile_protos("../proto/sensor.proto")?;
    println!("cargo:rerun-if-changed=../proto/sensor.proto");

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
