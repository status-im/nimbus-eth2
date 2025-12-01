#!/bin/bash

while read -r file; do
  commit="$(git -C "$file" rev-parse HEAD)"
  commit_date=$(TZ=UTC0 git -C "$file" show -s --format='%cd' --date=iso-local HEAD)
  if ! branch="$(git config -f .gitmodules --get "submodule.$file.branch")"; then
    echo "Submodule '$file': '.gitmodules' lacks 'branch' entry"
    exit 2
  fi
  # Without the `--depth=1` fetch, may run into 'error processing shallow info: 4'
  if ! error="$(git -C "$file" fetch -q --depth=1 origin "+refs/heads/${branch}:refs/remotes/origin/${branch}")"; then
    echo "Submodule '$file': Failed to fetch '$branch': $error (1)"
    exit 2
  fi
  branch_commit_date=$(TZ=UTC0 git -C "$file" show -s --format='%cd' --date=iso-local "refs/remotes/origin/${branch}")
  if [[ "${commit_date}" > "${branch_commit_date}" ]]; then
    echo "Submodule '$file': '$commit' ($commit_date) is more recent than latest '$branch' ($branch_commit_date) (branch config: '.gitmodules')"
    exit 2
  fi
  if ! error="$(git -C "$file" fetch -q --shallow-since="$commit_date" origin "+refs/heads/${branch}:refs/remotes/origin/${branch}")"; then
    echo "Submodule '$file': Failed to fetch '$branch': $error (2)"
    exit 2
  fi
  if ! git -C "$file" merge-base --is-ancestor "$commit" "refs/remotes/origin/$branch"; then
    echo "Submodule '$file': '$commit' is not on '$branch' as of $commit_date (branch config: '.gitmodules')"
    exit 2
  fi
done < <(git diff --name-only --diff-filter=AM HEAD^ | grep -f <(git config --file .gitmodules --get-regexp path | awk '{ print $2 }') || true)
