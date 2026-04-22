# beacon_chain
# Copyright (c) 2023-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

if [ -z "${GETH_BINARIES_SOURCED:-}" ]; then
GETH_BINARIES_SOURCED=1

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
BUILD_DIR="$(cd "$SCRIPTS_DIR/../build"; pwd)"

source "${SCRIPTS_DIR}/detect_platform.sh"
source "${SCRIPTS_DIR}/bash_utils.sh"

: ${CURL_BINARY:="curl"}
: ${STABLE_GETH_BINARY:="${BUILD_DIR}/downloads/geth$EXE_EXTENSION"}

download_geth_stable() {
  if [[ ! -e "${STABLE_GETH_BINARY}" ]]; then
    GETH_VERSION="1.17.2-be4dc0c4"  # https://geth.ethereum.org/downloads
    GETH_URL="https://gethstore.blob.core.windows.net/builds/"

    case "${OS}-${ARCH}" in
      linux-amd64|linux-x86_64)
        GETH_TARBALL="geth-linux-amd64-${GETH_VERSION}.tar.gz"
        ;;
      linux-arm64|linux-aarch64)
        GETH_TARBALL="geth-linux-arm64-${GETH_VERSION}.tar.gz"
        ;;
      macos-arm64|macos-aarch64)
        if command -v geth >/dev/null 2>&1; then
          mkdir -p "$(dirname "${STABLE_GETH_BINARY}")"
          cp -v "$(command -v geth)" "${STABLE_GETH_BINARY}"
          return 0
        elif command -v nix >/dev/null 2>&1; then
          GETH=$(nix build 'nixpkgs#go-ethereum' --no-link --print-out-paths)
          mkdir -p "$(dirname "${STABLE_GETH_BINARY}")"
          cp -v "${GETH}"/bin/geth "${STABLE_GETH_BINARY}"
          "${STABLE_GETH_BINARY}" --version
          return 0
        else
          echo "Geth unavailable either in path or via Nix; install e.g., via https://geth.ethereum.org/docs/getting-started/installing-geth#macos-via-homebrew"
          exit 1
        fi
        ;;
      windows-amd64|windows-x86_64)
        GETH_TARBALL="geth-windows-amd64-${GETH_VERSION}.zip"
        ;;
      *)
        echo "No Geth binaries available for platform: ${OS}-${ARCH}"
        exit 1
        ;;
    esac

    log "Downloading Geth binary"

    "${CURL_BINARY}" -sSLO --retry 3 --retry-all-errors "$GETH_URL/$GETH_TARBALL"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d geth-stable-tarball-XXX)
    CLEANUP_DIRS+=("$tmp_extract_dir")
    tar -xzf "$GETH_TARBALL" -C "$tmp_extract_dir" --strip-components=1
    mkdir -p "$(dirname "$STABLE_GETH_BINARY")"
    mv "$tmp_extract_dir/geth$EXE_EXTENSION" "$STABLE_GETH_BINARY"
    chmod +x "$STABLE_GETH_BINARY"
    patchelf_when_on_nixos "$STABLE_GETH_BINARY"
  fi
}

fi
