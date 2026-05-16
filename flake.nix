{
  description = "nimbus-eth2";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?rev=2a777ace4b722f2714cc06d596f2476ee628c04a";

    # Backfill source for gcc11/gcc12, pinned to nixos-25.05.
    # Intentionally does not follow nixpkgs since we need the older toolchains.
    nixpkgsGccCompat.url = "github:NixOS/nixpkgs?rev=ac62194c3917d5f474c1a844b6fd6da2db95077d";

    # WARNING: Do not use relative path, it breaks caching of NBS.
    # Remember to call 'nix flake update' when NBS is updated.
    nimbusBuildSystem = {
      url = "git+https://github.com/status-im/nimbus-build-system?submodules=1#";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    self = {
      # WARNING: Does not work with 'github:' schema URLs.
      # https://github.com/NixOS/nix/issues/14982
      submodules = true;
      # Avoid fetching big files from vendor/hoodi submodule.
      lfs = false;
    };
  };

  outputs = { self, nixpkgs, nixpkgsGccCompat, nimbusBuildSystem }:
    assert (builtins.compareVersions builtins.nixVersion "2.27") <= 0
      -> throw "Nix 2.27 or newer needed for proper submodules support!";
    let
      stableSystems = [
        "x86_64-linux" "aarch64-linux" "armv7a-linux"
        "x86_64-darwin" "aarch64-darwin"
        "x86_64-windows"
      ];

      forEach      = nixpkgs.lib.genAttrs;
      forAllSystems = forEach stableSystems;

      pkgsFor = forEach stableSystems (system:
        import nixpkgs {
          inherit system;
          overlays = [
            # Backfill gcc11/gcc12 from nixos-25.05; not present in primary nixpkgs.
            (final: prev: let
              compat = import nixpkgsGccCompat { inherit system; };
            in {
              gcc11 = compat.gcc11;
              gcc12 = compat.gcc12;
            })
          ];
        }
      );

    in rec {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor.${system};

          buildTarget = pkgs.callPackage ./nix/default.nix {
            inherit stableSystems self;
          };

          nim = nimbusBuildSystem.packages.${system}.nim;

          build = targets: gcc:
            buildTarget.override { inherit targets nim gcc; };

        in rec {
          beacon_node_gcc11 = build ["nimbus_beacon_node"] pkgs.gcc11;
          beacon_node_gcc12 = build ["nimbus_beacon_node"] pkgs.gcc12;
          beacon_node_gcc13 = build ["nimbus_beacon_node"] pkgs.gcc13;
          beacon_node_gcc14 = build ["nimbus_beacon_node"] pkgs.gcc14;
          beacon_node_gcc15 = build ["nimbus_beacon_node"] pkgs.gcc15;
          beacon_node       = beacon_node_gcc14;

          validator_client_gcc11 = build ["nimbus_validator_client"] pkgs.gcc11;
          validator_client_gcc12 = build ["nimbus_validator_client"] pkgs.gcc12;
          validator_client_gcc13 = build ["nimbus_validator_client"] pkgs.gcc13;
          validator_client_gcc14 = build ["nimbus_validator_client"] pkgs.gcc14;
          validator_client_gcc15 = build ["nimbus_validator_client"] pkgs.gcc15;
          validator_client       = validator_client_gcc14;

          signing_node = build ["nimbus_signing_node"] null;
          ncli         = build ["ncli"]               null;
          ncli_db      = build ["ncli_db"]            null;

          inherit (pkgs) go-ethereum;
          default = beacon_node;
        }
      );

      devShells = forAllSystems (system: {
        default = pkgsFor.${system}.callPackage ./nix/shell.nix { };
      });
    };
}
