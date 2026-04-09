{
  pkgs ? import <nixpkgs> { },
  # Source code of this repo.
  src ? ../.,
  # Nimbus-build-system package.
  nim ? null,
  # Options: nimbus_light_client, nimbus_validator_client, nimbus_signing_node, all
  targets ? ["nimbus_beacon_node"],
  # Options: 0,1,2
  verbosity ? 1,
  # These are the only platforms tested in CI and considered stable.
  stableSystems ? [
    "x86_64-linux" "aarch64-linux" "armv7a-linux"
    "x86_64-darwin" "aarch64-darwin"
    "x86_64-windows"
  ],
}:

# The 'or' is to handle src fallback to ../. which lack submodules attribue.
assert pkgs.lib.assertMsg ((src.submodules or true) == true)
  "Unable to build without submodules. Append '?submodules=1#' to the URI.";

let
  inherit (pkgs) stdenv lib writeScriptBin callPackage;

  revision = lib.substring 0 8 (src.rev or src.dirtyRev or "00000000");
in stdenv.mkDerivation rec {
  pname = "nimbus-eth2";
  version = "${callPackage ./version.nix {}}-${revision}";

  inherit src;

  nativeBuildInputs = let
    fakeGit = writeScriptBin "git" "echo ${version}";
  in
    with pkgs; [ nim which fakeGit ]
    ++ lib.optionals stdenv.isDarwin [ pkgs.darwin.cctools ];

  enableParallelBuilding = true;

  # Disable CPU optmizations that make binary not portable.
  NIMFLAGS = "-d:disableMarchNative -d:git_revision_override=${revision}";
  # Avoid errors about missing user home.
  NIMBLE_DIR = "/tmp";
  # Avoid Nim cache permission errors.
  XDG_CACHE_HOME = "/tmp";

  makeFlags = targets ++ [
    "V=${toString verbosity}"
    # Built from nimbus-build-system via flake.
    "USE_SYSTEM_NIM=1"
  ];

  patchPhase = ''
    patchShebangs scripts vendor/nimbus-build-system/scripts
  '';

  installPhase = ''
    mkdir -p $out/bin
    rm -f build/generate_makefile
    cp build/* $out/bin
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    for BINARY in $out/bin/*; do $BINARY --version; done
  '';

  meta = with lib; {
    homepage = "https://nimbus.guide/";
    downloadPage = "https://github.com/status-im/nimbus-eth2/releases";
    changelog = "https://github.com/status-im/nimbus-eth2/blob/stable/CHANGELOG.md";
    description = "Nimbus is a lightweight client for the Ethereum consensus layer";
    longDescription = ''
      Nimbus is an extremely efficient consensus layer client implementation.
      While it's optimised for embedded systems and resource-restricted devices --
      including Raspberry Pis, its low resource usage also makes it an excellent choice
      for any server or desktop (where it simply takes up fewer resources).
    '';
    license = with licenses; [asl20 mit];
    mainProgram = "nimbus_beacon_node";
    platforms = stableSystems;
  };
}
