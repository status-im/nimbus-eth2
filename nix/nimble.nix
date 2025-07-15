{ pkgs ? import <nixpkgs> { } }:

let
  tools = pkgs.callPackage ./tools.nix {};
  sourceFile = ../vendor/nimbus-build-system/vendor/Nim/koch.nim;
in pkgs.fetchFromGitHub {
  owner = "nim-lang";
  repo = "nimble";
  fetchSubmodules = true;
  rev = tools.findKeyValue "^ +NimbleStableCommit = \"([a-f0-9]+)\".*$" sourceFile;
  # WARNING: Requires manual updates when Nim compiler version changes.
  hash = "sha256-wgzFhModFkwB8st8F5vSkua7dITGGC2cjoDvgkRVZMs=";
}
