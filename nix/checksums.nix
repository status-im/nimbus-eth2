{ pkgs ? import <nixpkgs> { } }:

let
  tools = pkgs.callPackage ./tools.nix {};
  sourceFile = ../vendor/nimbus-build-system/vendor/Nim/koch.nim;
in pkgs.fetchFromGitHub {
  owner = "nim-lang";
  repo = "checksums";
  rev = tools.findKeyValue "^ +ChecksumsStableCommit = \"([a-f0-9]+)\".*$" sourceFile;
  # WARNING: Requires manual updates when Nim compiler version changes.
  hash = "sha256-JZhWqn4SrAgNw/HLzBK0rrj3WzvJ3Tv1nuDMn83KoYY=";
}
