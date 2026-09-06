fn main() {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(&["../proto/agent.proto"], &["../proto"])
        .expect("failed to compile proto/agent.proto");
    println!("cargo:rerun-if-changed=../proto/agent.proto");
}
