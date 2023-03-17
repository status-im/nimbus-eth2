if [ -z "${DETECT_PLATFORM_SOURCED:-}" ]; then
DETECT_PLATFORM_SOURCED=1

EXE_EXTENSION=""
BAT_EXTENSION=""

# OS detection
OS="linux"
if uname | grep -qi darwin; then
  OS="macos"
elif uname | grep -qiE "mingw|msys"; then
  OS="windows"
  EXE_EXTENSION=".exe"
  BAT_EXTENSION=".bat"
fi

# Architecture detection
ARCH="$(uname -m)"

fi
