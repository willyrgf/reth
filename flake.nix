{
  description = "A flake for building the reth project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];

        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree =
            true; # Needed for some potential dependencies or tools
        };

        # Select the rust toolchain
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        # Crane library for building Rust projects
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common arguments for crane builds
        commonArgs = {
          # Use cleanCargoSource if you face issues with generated files,
          # but craneLib.path is usually fine and faster.
          # src = craneLib.cleanCargoSource (craneLib.path ./.);
          src = (craneLib.path ./.);
          # Add a pname here to silence the warning for the cargoArtifacts build
          pname = "reth-workspace-deps";
          # Features based on Makefile (excluding jemalloc for non-linux potentially,
          # but Nix builds usually target Linux where jemalloc is fine)
          # Consider if 'min-debug-logs' is appropriate for release builds.
          cargoExtraArgs = "--features jemalloc,asm-keccak,min-debug-logs";

          buildInputs = with pkgs;
            [
              # Dependencies needed for linking
              openssl
              pkg-config
            ] ++ lib.optionals pkgs.stdenv.isLinux [
              # Linux specific dependencies if any (jemalloc is handled by feature flag)
            ];

          nativeBuildInputs = with pkgs; [
            # Tools needed during the build process itself
            pkg-config
            cmake # Often needed for C dependencies like libmdbx
            clang # Sometimes preferred/needed by cc crate
            llvmPackages.libclang # For bindgen if used
            perl # For sha3-asm build script
          ];

          # Environment variables from Makefile's reproducible build (optional, Nix handles reproducibility)
          # SOURCE_DATE_EPOCH = builtins.toString (self.lastModified or 0);
          # CARGO_INCREMENTAL = "0";
          # LC_ALL = "C";
          # TZ = "UTC";
          # MDBX might need specific flags, especially for cross-compiling (handled by crane/cc crate often)
          # JEMALLOC_SYS_WITH_LG_PAGE = "16"; # Example if needed for aarch64 builds
        };

        # Build cached dependencies
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build reth package
        reth = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "reth"; # This overrides the pname from commonArgs
        });

        # Build op-reth package
        op-reth = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "op-reth"; # This overrides the pname from commonArgs
          # Specify the binary and manifest path for op-reth
          cargoExtraArgs = commonArgs.cargoExtraArgs
            + " --bin op-reth --manifest-path crates/optimism/bin/Cargo.toml";
        });

        # Build MDBX tools (db-tools target)
        mdbx-tools = pkgs.stdenv.mkDerivation {
          pname = "mdbx-tools";
          version = "0.1.0"; # Placeholder version
          src = ./crates/storage/libmdbx-rs/mdbx-sys/libmdbx;
          nativeBuildInputs = with pkgs; [ gnumake gcc ];
          # Silence benchmark message as in Makefile
          makeFlags = [ "IOARENA=1" "tools" ];
          installPhase = ''
            mkdir -p $out/bin
            cp mdbx_chk $out/bin/
            cp mdbx_copy $out/bin/
            cp mdbx_dump $out/bin/
            cp mdbx_drop $out/bin/
            cp mdbx_load $out/bin/
            cp mdbx_stat $out/bin/
          '';
          # Ensure clean build environment
          preConfigure = ''
            make clean
          '';
        };

      in {

        packages = {
          inherit reth op-reth mdbx-tools;
          default = self.packages.${system}.reth;
        };

        apps = {
          reth = flake-utils.lib.mkApp { drv = self.packages.${system}.reth; };
          op-reth =
            flake-utils.lib.mkApp { drv = self.packages.${system}.op-reth; };
          default = self.apps.${system}.reth;
        };

        # Development shell providing tools from Makefile
        devShells.default = pkgs.mkShell {
          inputsFrom = [
            self.packages.${system}.reth
            self.packages.${system}.op-reth
            self.packages.${system}.mdbx-tools
          ];

          # Use the same nativeBuildInputs as the build itself, plus shell-specific tools
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ (with pkgs; [
             cargo-nextest
             # Add cacert for potential network access in shell commands
             cacert
          ]);

          buildInputs = with pkgs; commonArgs.buildInputs ++ [
            # Rust toolchain components
            rustToolchain

            # Linting/Formatting tools from Makefile
            codespell
            dprint

            # Other tools potentially used
            gdb # For debugging

            # Tools for docker targets (if needed locally)
            # docker
            # docker-buildx

            # Tools for EF tests (might need specific libs/tools)
            wget
            gnutar

            # Tools for coverage
            # llvmPackages.tools # for llvm-cov

            # Tools for cross-compilation (if desired in shell)
            # cross
          ];

          # Environment variables for development
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          # RUSTFLAGS = "-C link-arg=-lgcc"; # Example from Makefile cross-compile, adjust if needed

          # Add cargo-audit (optional security check)
          # buildInputs = buildInputs ++ [ pkgs.cargo-audit ];
          # shellHook = ''
          #   echo "Running cargo audit..."
          #   cargo audit --db ${advisory-db}
          # '';
          # Add pre-commit hook integration (optional)
          # buildInputs = buildInputs ++ [ pkgs.pre-commit ];
          # shellHook = ''
          #   pre-commit install -f --install-hooks
          #   echo "Pre-commit hooks installed."
          # '';
          shellHook = ''
            echo "Reth Nix development environment activated."
            echo "Provided packages: reth, op-reth, mdbx-tools"
            echo "Toolchain: $(rustc --version)"
            # Add other useful info or setup steps here
          '';
        };

        # Add a formatter check using dprint (matches lint-toml)
        formatter = pkgs.dprint;

        # Add checks (optional, can be slow)
        checks = {
          # Check formatting
          formatting = pkgs.runCommand "fmt-check" {
            nativeBuildInputs = [ pkgs.dprint ];
            # Pass src directly to runCommand environment
            src = commonArgs.src;
          } ''
            # Set HOME to a writable directory within the build sandbox
            export HOME=$(mktemp -d)
            # Change to the source directory
            cd $src
            # Run dprint check
            ${pkgs.dprint}/bin/dprint check
            # Create the output file expected by Nix
            touch $out
          '';

          # Run clippy (matches clippy target)
          clippy = pkgs.runCommand "clippy-check" {
            nativeBuildInputs = [ rustToolchain pkgs.cacert ] # Add cacert for network access
              ++ commonArgs.nativeBuildInputs;
            buildInputs = commonArgs.buildInputs;
            # Pass src directly to runCommand environment
            src = commonArgs.src;
          } ''
            # Set CARGO_HOME and RUSTUP_HOME to writable directories
            export CARGO_HOME=$(mktemp -d)
            export RUSTUP_HOME=$(mktemp -d)
            # Store the writable build root (current directory)
            BUILD_ROOT=$(pwd)
            # Change to the source directory
            cd $src
            # Ensure RUST_SRC_PATH is set
            export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"
            # Run clippy, directing target output to a writable location
            cargo clippy --target-dir $BUILD_ROOT/target --all-targets --all-features -- -D warnings
            # Create the output file expected by Nix
            touch $out
          '';

          # Run tests using craneLib.cargoNextest
          unit-tests = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            # Add cargo-nextest and cacert to nativeBuildInputs
            # craneLib might add cargo-nextest automatically, but being explicit is safe.
            nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.cargo-nextest pkgs.cacert ];
            # Arguments for cargo nextest run
            # Exclude benchmarks, run other tests. Removed problematic 'jemalloc-prof' feature for check.
            # If specific features ARE needed for tests, add them back with --features flag.
            cargoNextestExtraArgs = "--locked --workspace -E 'kind(bench)'";
            # Override pname for clarity in logs
            pname = "reth-unit-tests";
          });

          # Check for spelling errors (matches lint-codespell)
          codespell = pkgs.runCommand "codespell-check" {
            nativeBuildInputs = [ pkgs.codespell ];
            # Pass src directly to runCommand environment
            src = commonArgs.src;
          } ''
            # Change to the source directory
            cd $src
            # Run codespell
            ${pkgs.codespell}/bin/codespell --skip "*.json,./testing/ef-tests/ethereum-tests"
            # Create the output file expected by Nix
            touch $out
          '';
        };
      });
}
