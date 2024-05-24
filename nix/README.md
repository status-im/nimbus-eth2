# Usage

## Shell

A development shell can be started using:
```sh
nix develop
```

## Building

To build a beacon node you can use:
```sh
nix build '.?submodules=1#beacon_node'
```
The `?submodules=1` part should eventually not be necessary.
For more details see:
https://github.com/NixOS/nix/issues/4423

It can be also done without even cloning the repo:
```sh
nix build 'github:status-im/nimbus-eth2?submodules=1'
```

## Running

```sh
nix run 'github:status-im/nimbus-eth2?submodules=1'
```
