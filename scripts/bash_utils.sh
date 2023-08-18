if [ -z "${BASH_UTILS_SOURCED:-}" ]; then
BASH_UTILS_SOURCED=1

VERBOSE="0"

log() {
  if [[ "${VERBOSE}" -ge "1" ]]; then
    echo "${@}"
  fi
}

run() {
  echo Launching: $*
  $*
}

fi
