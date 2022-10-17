{ pkgs ? import <nixpkgs> {}}:
with pkgs;
mkShell {

  buildInputs = [
    figlet
    git
    gnumake

    # For installing ganache for local simulations
    nodePackages.ganache-cli
  ] ++ lib.optionals (!stdenv.isDarwin) [
    lsb-release
  ];

  shellHook = ''
    # By default, the Nix wrapper scripts for executing the system compilers
    # will erase `-march=native` because this introduces impurity in the build.
    # For the purposes of compiling Nimbus, this behavior is not desired:
    export NIX_ENFORCE_NO_NATIVE=0

    figlet "Welcome to Nimbus-eth2"
  '';
}
