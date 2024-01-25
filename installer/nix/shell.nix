# beacon_chain
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{ pkgs ? import <nixpkgs> {}}:
let
  mkdocs-packages = ps: with ps; [
    mkdocs
    mkdocs-material
    mkdocs-material-extensions
    pymdown-extensions
  ];
  mkdocs-python = pkgs.python3.withPackages mkdocs-packages;
in
with pkgs;
mkShell {

  buildInputs = [
    figlet
    git
    git-lfs
    gnumake
    getopt

    # For the local simulation
    openssl # for generating the JWT file
    lsof    # for killing processes by port
    killall # for killing processes manually
    curl    # for working with the node APIs
    openjdk # for running web3signer

    mkdocs-python
  ] ++ lib.optionals (!stdenv.isDarwin) [
    lsb-release
  ];

  shellHook = ''
    # By default, the Nix wrapper scripts for executing the system compilers
    # will erase `-march=native` because this introduces impurity in the build.
    # For the purposes of compiling Nimbus, this behavior is not desired:
    export NIX_ENFORCE_NO_NATIVE=0
    export USE_SYSTEM_GETOPT=1

    figlet "Welcome to Nimbus-eth2"
  '';
}
