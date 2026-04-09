# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

if [ -z "${SPAMOOR_BINARIES_SOURCED:-}" ]; then
SPAMOOR_BINARIES_SOURCED=1

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
BUILD_DIR="$(cd "$SCRIPTS_DIR/../build"; pwd)"

source "${SCRIPTS_DIR}/detect_platform.sh"
source "${SCRIPTS_DIR}/bash_utils.sh"

: ${CURL_BINARY:="curl"}
: ${STABLE_SPAMOOR_BINARY:="${BUILD_DIR}/downloads/spamoor$EXE_EXTENSION"}

download_spamoor_stable() {
  if [[ ! -e "${STABLE_SPAMOOR_BINARY}" ]]; then
    SPAMOOR_VERSION="1.1.11" # https://github.com/ethpandaops/spamoor/tags
    SPAMOOR_URL="https://github.com/ethpandaops/spamoor/releases/download/v${SPAMOOR_VERSION}/"

    case "${OS}-${ARCH}" in
      linux-amd64|linux-x86_64)
        SPAMOOR_TARBALL="spamoor_${SPAMOOR_VERSION}_linux_amd64.tar.gz"
        ;;
      linux-arm64|linux-aarch64)
        SPAMOOR_TARBALL="spamoor_${SPAMOOR_VERSION}_linux_arm64.tar.gz"
        ;;
      macos-arm64|macos-aarch64)
        SPAMOOR_TARBALL="spamoor_${SPAMOOR_VERSION}_darwin_arm64.tar.gz"
        ;;
      windows-amd64|windows-x86_64)
        SPAMOOR_TARBALL="spamoor_${SPAMOOR_VERSION}_windows_amd64.zip"
        ;;
      *)
        echo "No Spamoor binaries available for platform: ${OS}-${ARCH}"
        exit 1
        ;;
    esac

    log "Downloading Spamoor binary"

    "$CURL_BINARY" -sSLO "$SPAMOOR_URL/$SPAMOOR_TARBALL"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d spamoor-stable-tarball-XXX)
    CLEANUP_DIRS+=("$tmp_extract_dir")
    tar -xzf "$SPAMOOR_TARBALL" -C "$tmp_extract_dir" --strip-components=1
    mkdir -p "$(dirname "$STABLE_SPAMOOR_BINARY")"
    mv "$tmp_extract_dir/spamoor$EXE_EXTENSION" "$STABLE_SPAMOOR_BINARY"
    chmod +x "$STABLE_SPAMOOR_BINARY"
    patchelf_when_on_nixos "$STABLE_SPAMOOR_BINARY"
  fi
}

fi
