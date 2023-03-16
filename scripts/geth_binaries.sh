if [ -z "${GETH_BINARIES_SOURCED:-}" ]; then
GETH_BINARIES_SOURCED=1

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
BUILD_DIR="$(cd "$SCRIPTS_DIR/../build"; pwd)"

source "${SCRIPTS_DIR}/detect_platform.sh"
source "${SCRIPTS_DIR}/bash_utils.sh"

: ${CURL_BINARY:="curl"}
: ${STABLE_GETH_BINARY:="${BUILD_DIR}/downloads/geth$EXE_EXTENSION"}
: ${GETH_CAPELLA_BINARY:="${BUILD_DIR}/downloads/geth_capella$EXE_EXTENSION"}
: ${GETH_DENEB_BINARY:="${BUILD_DIR}/downloads/geth_deneb$EXE_EXTENSION"}

download_geth_stable() {
  if [[ ! -e "${STABLE_GETH_BINARY}" ]]; then
    GETH_VERSION="1.10.26-e5eb32ac"
    GETH_URL="https://gethstore.blob.core.windows.net/builds/"

    case "${OS}-${ARCH}" in
      linux-amd64|linux-x86_64)
        GETH_TARBALL="geth-linux-amd64-${GETH_VERSION}.tar.gz"
        ;;
      linux-arm64|linux-aarch64)
        GETH_TARBALL="geth-linux-arm64-${GETH_VERSION}.tar.gz"
        ;;
      macos-amd64|macos-x86_64)
        GETH_TARBALL="geth-darwin-amd64-${GETH_VERSION}.tar.gz"
        ;;
      macos-arm64|macos-aarch64)
        # There is no official binary for macOS/ARM at the moment
        # The AMD64 binary should work under Rosetta
        GETH_TARBALL="geth-darwin-amd64-${GETH_VERSION}.tar.gz"
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

    "$CURL_BINARY" -sSLO "$GETH_URL/$GETH_TARBALL"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d geth-stable-tarball-XXX)
    CLEANUP_DIRS+=("$tmp_extract_dir")
    tar -xzf "$GETH_TARBALL" -C "$tmp_extract_dir" --strip-components=1
    mkdir -p "$(dirname "$STABLE_GETH_BINARY")"
    mv "$tmp_extract_dir/geth$EXE_EXTENSION" "$STABLE_GETH_BINARY"
    chmod +x "$STABLE_GETH_BINARY"
  fi
}

download_status_geth_binary() {
  BINARY_NAME="$1"
  BINARY_FS_PATH="$2"

  if [[ ! -e "${BINARY_FS_PATH}" ]]; then
    case "${OS}-${ARCH}" in
      linux-amd64|linux-x86_64)
        GETH_PLATFORM=linux-amd64
        ;;
      linux-arm64|linux-aarch64)
        GETH_PLATFORM=linux-arm64
        ;;
      macos-amd64|macos-x86_64)
        GETH_PLATFORM=macos-amd64
        ;;
      macos-arm64|macos-aarch64)
        GETH_PLATFORM=macos-arm64
        ;;
      windows-amd64|windows-x86_64)
        GETH_PLATFORM=windows-amd64
        ;;
      *)
        echo "No Status Geth binaries available for platform: ${OS}-${ARCH}"
        exit 1
        ;;
    esac

    log "Downloading Status geth binary ($1)"

    GETH_TARBALL_NAME="geth-binaries-${GETH_PLATFORM}.tar.gz"
    GETH_TARBALL_URL="https://github.com/status-im/nimbus-simulation-binaries/releases/download/latest/${GETH_TARBALL_NAME}"
    GETH_BINARY_IN_TARBALL="geth/${BINARY_NAME}/geth$EXE_EXTENSION"

    "$CURL_BINARY" -o "$GETH_TARBALL_NAME" -sSL "$GETH_TARBALL_URL"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d geth-status-tarball-XXX)
    CLEANUP_DIRS+=("$tmp_extract_dir")
    tar -xzf "$GETH_TARBALL_NAME" -C "$tmp_extract_dir" --strip-components 2 \
      "$GETH_BINARY_IN_TARBALL"
    mkdir -p "$(dirname "$BINARY_FS_PATH")"
    mv "$tmp_extract_dir/geth$EXE_EXTENSION" "$BINARY_FS_PATH"
    chmod +x "$BINARY_FS_PATH"
  fi
}

download_geth_capella() {
  download_status_geth_binary withdrawals-timestamp "$GETH_CAPELLA_BINARY"
}

download_geth_deneb() {
  download_status_geth_binary eip-4844 "$GETH_DENEB_BINARY"
}

fi
