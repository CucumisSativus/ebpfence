fn main() {
    tonic_build::compile_protos("../proto/ebpfence.proto")
        .expect("proto compilation failed");

    println!("cargo:rerun-if-changed=../proto/ebpfence.proto");
}
