# Usage

## Shell

A development shell can be started using:
```sh
nix develop
```

## Building

To build a beacon node you can use:
```sh
nix build .
```
It can be also done without even cloning the repo:
```sh
nix build 'git+https://github.com/status-im/nimbus-eth2'
```
When using `github:` schema the `?submodules=1#` argument is required:
```sh
nix build 'github:status-im/nimbus-eth2?submodules=1#'
```
This is [a known issue with `github:` schema](https://github.com/NixOS/nix/issues/14982) as well [as a URI parsing bug in Nix](https://github.com/NixOS/nix/issues/6633).

## Running

```sh
nix run 'git+https://github.com/status-im/nimbus-eth2'
```

## Debugging

Debug symbols are available in `$debug` output separate from defualt `$out`, which needs to be built.

### Linux

```nix
nix build '.#beacon_node^out,debug'
gdb -iex "set debug-file-directory $PWD/result-debug/lib/debug" ./result/bin/nimbus_beacon_node
```
If using patched `gdb` from `nixpkgs` this is enough:
```
export NIX_DEBUG_INFO_DIRS="$PWD/result-debug/lib/debug"
```

### MacOS

```
> lldb
(lldb) target create ./result/bin/nimbus_beacon_node --symfile ./result-debug/lib/debug/nimbus_beacon_node.dSYM
(lldb) breakpoint set --name main
(lldb) run
```
