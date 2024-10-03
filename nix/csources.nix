{ pkgs ? import <nixpkgs> { } }:

let
  tools = pkgs.callPackage ./tools.nix {};
  sourceFile = ../vendor/nimbus-build-system/vendor/Nim/config/build_config.txt;
in pkgs.fetchFromGitHub {
  owner = "nim-lang";
  repo = "csources_v2";
  rev = tools.findKeyValue "^nim_csourcesHash=([a-f0-9]+)$" sourceFile;
  # WARNING: Requires manual updates when Nim compiler version changes.
  hash = "sha256-UCLtoxOcFYjBdvHx7A47x6FjLMi6VZqpSs65MN7fpBs=";
}
