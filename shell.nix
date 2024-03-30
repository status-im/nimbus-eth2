{
  pkgs ? import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/ae32f552b46fea56c8873504e8a199f68faa2d7f.tar.gz";
    sha256 = "sha256:1f87khhzq276wcs2zpijzp3naf95jv4ijransrd21ybp283kahgp";
  }) {}
}:

assert pkgs.lib.assertMsg (pkgs.nim1.version == "1.6.18")
  "Unable to build with Nim ${pkgs.nim1.version}, only 1.6.18 allowed.";

pkgs.mkShell {
  name = "nimbus-eth2-shell";

  # Versions dependent on nixpkgs commit. Update manually.
  buildInputs = with pkgs; [
    gcc12   # 12.3.0
    nim1    # 1.6.18
    git     # 2.44.0
    git-lfs # 3.5.1
    which   # 2.21
    curl    # 8.6.0
    jq      # 1.7.1
    gawk    # 5.2.2
  ] ++ lib.optionals stdenv.isDarwin [
    llvm_17 # 17.0.6
  ];

  # Nim provided by Nix speeds up builds, but needs to be kept updated.
  shellHook = ''
    export MAKEFLAGS="-j$NIX_BUILD_CORES USE_SYSTEM_NIM=1"
  '';
}
