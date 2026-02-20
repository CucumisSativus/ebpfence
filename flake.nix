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
            bpftools
          ];

          # Point clang at the libbpf and kernel headers provided by Nix
          shellHook = ''
            export CGO_ENABLED=0
            export PATH="$(go env GOPATH)/bin:$PATH"

            # The Nix clang wrapper injects several hardening flags that are
            # unsupported for the BPF target used by bpf2go. Strip them so
            # `go generate ./daemon/` works without errors or warnings.
            export NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/zerocallusedregs/}"
            export NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/stackprotector/}"
            export NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/stackclashprotection/}"

            echo "eBPFence dev shell ready."
            echo "  clang:   $(clang --version | head -1)"
            echo "  go:      $(go version)"
            echo "  protoc:  $(protoc --version)"
          '';
        };
      }
    );
}
