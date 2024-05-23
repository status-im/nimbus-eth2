{ pkgs ? import <nixpkgs> { } }:

let
  tools = pkgs.callPackage ./tools.nix {};
  source = ../beacon_chain/version.nim;

  major = tools.findKeyValue "  versionMajor\\* = ([0-9]+)$" source;
  minor = tools.findKeyValue "  versionMinor\\* = ([0-9]+)$" source;
  build = tools.findKeyValue "  versionBuild\\* = ([0-9]+)$" source;
in
  "${major}.${minor}.${build}"
