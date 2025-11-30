#!/bin/bash

problematic_files=()
while read -r file; do
  if ! grep -qE '^{\.push raises: \[\](, gcsafe)?\.}$' "$file"; then
    problematic_files+=("$file")
  fi
done < <(git diff --name-only --diff-filter=AM --ignore-submodules HEAD^ | grep -E '\.nim$' || true)

if (( ${#problematic_files[@]} )); then
  echo "The following files do not have '{.push raises: [], gcsafe.}' (gcsafe optional):"
  for file in "${problematic_files[@]}"; do
    echo "- $file"
  done
  echo "See https://status-im.github.io/nim-style-guide/errors.exceptions.html"
  exit 2
fi
