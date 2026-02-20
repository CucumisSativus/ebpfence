{
  description = "eBPFence development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "ebpfence";

          packages = with pkgs; [
            # Go toolchain
            go

            # eBPF compilation (bpf2go uses clang to compile .bpf.c files)
            clang
            llvm

            # libbpf headers required when compiling BPF C code
            libbpf
            pkg-config

            # Linux kernel headers (provides <linux/bpf.h> etc.)
            linuxHeaders

            # Protobuf compiler (used by go generate ./proto/)
            protobuf

            # Useful eBPF debugging tool
            bpftool
          ];

          # Point clang at the libbpf and kernel headers provided by Nix
          shellHook = ''
            export CGO_ENABLED=0
            echo "eBPFence dev shell ready."
            echo "  clang:   $(clang --version | head -1)"
            echo "  go:      $(go version)"
            echo "  protoc:  $(protoc --version)"
          '';
        };
      }
    );
}
