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

        # Packages required to build the project (BPF compilation + Rust linking).
        # libbpf in buildInputs causes the Nix clang wrapper to inject
        # -I${libbpf}/include into all clang invocations, making
        # <bpf/bpf_helpers.h> etc. available for BPF C compilation.
        buildDeps = with pkgs; [
          # Rust toolchain
          rustc
          cargo
          rustfmt
          clippy

          # BPF C compilation (libbpf-cargo calls clang internally)
          clang
          llvm

          # libbpf headers — injected into clang by the Nix wrapper
          libbpf

          # libbpf-sys (vendored libbpf build) needs libelf and zlib via pkg-config
          elfutils.dev
          zlib.dev
          pkg-config

          # Linux kernel headers for BPF programs
          linuxHeaders

          # protoc — required by tonic-build to compile .proto files
          protobuf

          # eBPF introspection
          bpftools
        ];

        # Hardening flags injected by the Nix clang wrapper that are
        # unsupported for the BPF target — strip them so `cargo build` works.
        stripBpfHardeningFlags = ''
          export NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/zerocallusedregs/}"
          export NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/stackprotector/}"
          export NIX_HARDENING_ENABLE="''${NIX_HARDENING_ENABLE/stackclashprotection/}"
        '';
      in
      {
        # Default shell for day-to-day development.
        devShells.default = pkgs.mkShell {
          name = "ebpfence";
          packages = buildDeps ++ [ pkgs.rust-analyzer ];

          shellHook = stripBpfHardeningFlags + ''
            echo "eBPFence dev shell ready."
            echo "  rustc:  $(rustc --version)"
            echo "  cargo:  $(cargo --version)"
            echo "  clang:  $(clang --version | head -1)"
          '';
        };

        # Minimal shell for running integration tests on a CI/test machine.
        # Usage:
        #   nix develop .#integration
        #   sudo -E cargo test -p ebpfence-daemon --features integration -- --test-threads=1
        devShells.integration = pkgs.mkShell {
          name = "ebpfence-integration";
          packages = buildDeps;

          shellHook = stripBpfHardeningFlags + ''
            echo "eBPFence integration test shell ready."
            echo "  rustc:  $(rustc --version)"
            echo "  cargo:  $(cargo --version)"
            echo ""
            echo "Run integration tests with:"
            echo "  sudo -E cargo test -p ebpfence-daemon --features integration -- --test-threads=1"
          '';
        };
      }
    );
}
