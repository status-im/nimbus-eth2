{
  pkgs ? import <nixpkgs> { },
  # Source code of this repo.
  src ? ../.,
  # Options: nimbus_light_client, nimbus_validator_client, nimbus_signing_node, all
  targets ? ["nimbus_beacon_node"],
  # Options: 0,1,2
  verbosity ? 2,
  # Perform 2-stage bootstrap instead of 3-stage to save time.
  quickAndDirty ? true,
  # These are the only platforms tested in CI and considered stable.
  stableSystems ? [
    "x86_64-linux" "aarch64-linux" "armv7a-linux"
    "x86_64-darwin" "aarch64-darwin"
    "x86_64-windows"
  ],
}:

let
  inherit (pkgs) stdenv lib writeScriptBin callPackage;

  revision = lib.substring 0 8 (src.rev or "unknown");
in stdenv.mkDerivation rec {
  pname = "nimbus-eth2";
  version = "${callPackage ./version.nix {}}-${revision}";

  inherit src;

  # Fix for Nim compiler calling 'git rev-parse' and 'lsb_release'.
  nativeBuildInputs = let
    fakeGit = writeScriptBin "git" "echo ${version}";
    fakeLsbRelease = writeScriptBin "lsb_release" "echo nix";
  in
    with pkgs; [ fakeGit fakeLsbRelease which cmake ]
    ++ lib.optionals stdenv.isDarwin [ pkgs.darwin.cctools ];

  enableParallelBuilding = true;

  # Disable CPU optmizations that make binary not portable.
  NIMFLAGS = "-d:disableMarchNative -d:git_revision_override=${revision}";
  # Avoid Nim cache permission errors.
  XDG_CACHE_HOME = "/tmp";

  makeFlags = targets ++ [
    "V=${toString verbosity}"
    # TODO: Compile Nim in a separate derivation to save time.
    "QUICK_AND_DIRTY_COMPILER=${if quickAndDirty then "1" else "0"}"
    "QUICK_AND_DIRTY_NIMBLE=${if quickAndDirty then "1" else "0"}"
  ];

  # Generate the nimbus-build-system.paths file.
  configurePhase = ''
    patchShebangs scripts vendor/nimbus-build-system > /dev/null
    make nimbus-build-system-paths
  '';

  # Avoid nimbus-build-system invoking `git clone` to build Nim.
  preBuild = ''
    pushd vendor/nimbus-build-system/vendor/Nim
    mkdir dist
    cp -r ${callPackage ./nimble.nix {}}    dist/nimble
    chmod 777 -R dist/nimble
    mkdir -p dist/nimble/dist
    cp -r ${callPackage ./sat.nix {}}       dist/nimble/dist/sat
    cp -r ${callPackage ./checksums.nix {}} dist/checksums
    cp -r ${callPackage ./checksums.nix {}} dist/nimble/dist/checksums   # todo, dup?
    cp -r ${callPackage ./csources.nix {}}  csources_v2
    chmod 777 -R dist/nimble csources_v2
    popd
  '';

  installPhase = ''
    mkdir -p $out/bin
    rm -f build/generate_makefile
    cp build/* $out/bin
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
