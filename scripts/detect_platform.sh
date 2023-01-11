if [ -z "${DETECT_PLATFORM_SOURCED:-}" ]; then
DETECT_PLATFORM_SOURCED=1

# OS detection
OS="linux"
if uname | grep -qi darwin; then
  OS="macos"
elif uname | grep -qiE "mingw|msys"; then
  OS="windows"
fi

# Architecture detection
ARCH="$(uname -m)"

fi
