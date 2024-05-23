{
  description = "nimbus-eth2";

  inputs.nixpkgs.url = github:NixOS/nixpkgs/master;

  outputs = { self, nixpkgs }:
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

        default = beacon_node;
      });

      devShells = forAllSystems (system: {
        default = pkgsFor.${system}.callPackage ./nix/shell.nix { };
      });
    };
}
