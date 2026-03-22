use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Compile BPF C source into a Rust skeleton
    libbpf_cargo::SkeletonBuilder::new()
        .source("../bpf/deny_new_reads.bpf.c")
        .clang_args([
            "-I../bpf",      // vmlinux.h lives here
            "-I/usr/include/bpf",
        ])
        .build_and_generate(out_dir.join("deny_new_reads.skel.rs"))
        .expect("BPF skeleton generation failed");

    println!("cargo:rerun-if-changed=../bpf/deny_new_reads.bpf.c");
    println!("cargo:rerun-if-changed=../bpf/vmlinux.h");

    // Generate tonic/prost stubs from the proto file
    tonic_build::compile_protos("../proto/ebpfence.proto")
        .expect("proto compilation failed");

    println!("cargo:rerun-if-changed=../proto/ebpfence.proto");
}
