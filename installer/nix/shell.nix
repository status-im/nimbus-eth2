{ pkgs ? import <nixpkgs> { } }: with pkgs;
mkShell {
  buildInputs = [
    llvmPackages_14.clang-unwrapped
    figlet
    git
    gnumake

    # For installing ganache for local simulations
    nodePackages.ganache-cli
  ] ++ lib.optionals (!stdenv.isDarwin) [
    lsb-release
  ];

  shellHook = ''
    # We use clang unwrapped because the compiler wrappers under Nix
    # ignore -march=native in order to keep the build deterministic
    export PATH=${llvmPackages_14.clang-unwrapped}/bin:$PATH
    export CC=clang

    figlet "Welcome to Nimbus-eth2"
  '';
}
