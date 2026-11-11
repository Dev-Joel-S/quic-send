{
  description = "quic-send: send files and folders from one computer to another, peer to peer over QUIC";

  # nixpkgs as the tarball of its channel. flake.lock pins the exact revision.
  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs =
    { self, nixpkgs }:
    let
      # Only what was actually built and tested with this flake
      systems = [ "x86_64-linux" ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      version = (builtins.fromTOML (builtins.readFile ./qs-cli/Cargo.toml)).package.version;

      # The whole workspace as one package: `qsend` and the rendezvous server
      # `qs-rendezvous`. The crates come from Cargo.lock, with the checksums in there.
      package =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "quic-send";
          inherit version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;

          cargoBuildFlags = [
            "--package"
            "qs-cli"
            "--package"
            "qs-rendezvous"
          ];
          # The tests of the whole workspace, they only need the loopback interface
          cargoTestFlags = [ "--workspace" ];

          # The crypto library aws-lc comes from nixpkgs instead of being built from the
          # copy inside the aws-lc-sys crate, which is how nixpkgs wants Rust packages
          # to use it. The tests run the post-quantum key exchange with it.
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.aws-lc ];

          meta = {
            description = "Send files and folders from one computer to another, peer to peer over QUIC";
            homepage = "https://github.com/dev-joel-s/quic-send";
            license = pkgs.lib.licenses.mit;
            mainProgram = "qsend";
            platforms = systems;
          };
        };
    in
    {
      packages = forEachSystem (pkgs: rec {
        quic-send = package pkgs;
        default = quic-send;
      });

      # `nix flake check` builds the package, which runs the tests
      checks = forEachSystem (pkgs: {
        inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) quic-send;
      });

      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.quic-send ];
          packages = [
            pkgs.clippy
            pkgs.rustfmt
          ];
          # Like in the package: link the aws-lc of nixpkgs instead of building the
          # copy inside the crate
          env.AWS_LC_SYS_USE_SYSTEM = "1";
        };
      });

      formatter = forEachSystem (pkgs: pkgs.nixfmt);
    };
}
