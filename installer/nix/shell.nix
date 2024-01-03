{ pkgs ? import <nixpkgs> {}}:
with pkgs;
mkShell {

  buildInputs = [
    figlet
    git
    git-lfs
    gnumake

    # For the local simulation
    openssl # for generating the JWT file
    lsof    # for killing processes by port
    killall # for killing processes manually
    curl    # for working with the node APIs

    python3
    mdbook
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
