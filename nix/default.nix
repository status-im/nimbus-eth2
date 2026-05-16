{
  pkgs ? import <nixpkgs> { },
  # Source code of this repo.
  self ? {},
  # Nimbus-build-system package.
  nim ? null,
  # GCC version to compile the target with.
  gcc ? null,
  # Options: nimbus_light_client, nimbus_validator_client, nimbus_signing_node, all
  targets ? ["nimbus_beacon_node"],
  # Options: TRACE, DEBUG, INFO, NOTICE, WARN, ERROR, FATAL, NONE
  highestLogLevel ? "DEBUG",
  # Options: 0,1,2
  verbosity ? 1,
  # These are the only platforms tested in CI and considered stable.
  stableSystems ? [
    "x86_64-linux" "aarch64-linux" "armv7a-linux"
    "x86_64-darwin" "aarch64-darwin"
    "x86_64-windows"
  ],
}:

# The 'or' is to handle self fallback to {} which lack submodules attribute.
assert pkgs.lib.assertMsg ((self.submodules or true) == true)
  "Unable to build without submodules. Append '?submodules=1#' to the URI.";

let
  inherit (pkgs) lib writeScriptBin callPackage;

  stdenv =
    if gcc != null && !pkgs.stdenv.isDarwin
    then pkgs.overrideCC pkgs.stdenv gcc
    else pkgs.stdenv;

  revision = lib.substring 0 8 (self.rev or self.dirtyRev or "00000000");
in stdenv.mkDerivation rec {
  pname = "nimbus-eth2";
  version = "${callPackage ./version.nix {}}-${revision}";

  src = lib.fileset.toSource {
    root = ./..;
    fileset = lib.fileset.unions [
      ./../Makefile ./../beacon_chain.nimble ./../config.nims
      ./../beacon_chain ./../ncli ./../scripts ./../vendor ./../tools
    ];
  };


  nativeBuildInputs = let
    fakeGit = writeScriptBin "git" "echo ${version}";
  in
    with pkgs; [ nim which fakeGit ]
    ++ lib.optionals stdenv.isDarwin [ pkgs.darwin.cctools ];

  enableParallelBuilding = true;

  env = {
    # Disable CPU optimizations that make binary not portable.
    NIMFLAGS = "-d:disableMarchNative -d:git_revision_override=${revision}";
    # Avoid errors about missing user home.
    NIMBLE_DIR = "/tmp";
    # Avoid Nim cache permission errors.
    XDG_CACHE_HOME = "/tmp";
  };

  makeFlags = targets ++ [
    "V=${toString verbosity}"
    # Built from nimbus-build-system via flake.
    "USE_SYSTEM_NIM=1"
    # Define highest available log level.
    "LOG_LEVEL=${highestLogLevel}"
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
    for BINARY in $out/bin/*; do
      case "$(basename "$BINARY")" in
        ncli|ncli_db)
          # These don't support --version, just verify they execute.
          $BINARY --help > /dev/null 2>&1
          ;;
        *)
          $BINARY --version
          ;;
      esac
    done
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
