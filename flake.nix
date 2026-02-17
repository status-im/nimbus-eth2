{
  description = "nimbus-eth2";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?rev=2a777ace4b722f2714cc06d596f2476ee628c04a";
    self = {
      # WARNING: Does not work with 'github:' schema URLs.
      # https://github.com/NixOS/nix/issues/14982
      submodules = true;
      # Avoid fetching big files from vendor/hoodi submodule.
      lfs = false;
    };
  };

  outputs = { self, nixpkgs }:
    assert (builtins.compareVersions builtins.nixVersion "2.27") <= 0
      -> throw "Nix 2.27 or newer needed for proper submodules support!";

    let
      stableSystems = [
        "x86_64-linux" "aarch64-linux" "armv7a-linux"
        "x86_64-darwin" "aarch64-darwin"
        "x86_64-windows"
      ];
      forEach = nixpkgs.lib.genAttrs;
      forAllSystems = forEach stableSystems;
      pkgsFor = forEach stableSystems (
        system: import nixpkgs { inherit system; }
      );
    in rec {
      packages = forAllSystems (system: let
        buildTarget = pkgsFor.${system}.callPackage ./nix/default.nix {
          inherit stableSystems; src = self;
        };
        build = targets: buildTarget.override { inherit targets; };
      in rec {
        beacon_node      = build ["nimbus_beacon_node"];
        signing_node     = build ["nimbus_signing_node"];
        validator_client = build ["nimbus_validator_client"];
        ncli             = build ["ncli"];
        ncli_db          = build ["ncli_db"];

        # Useful for tests
        inherit (pkgsFor.${system}) go-ethereum;

        default = beacon_node;
      });

      devShells = forAllSystems (system: {
        default = pkgsFor.${system}.callPackage ./nix/shell.nix { };
      });
    };
}
