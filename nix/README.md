# Usage

## Shell

A development shell can be started using:
```sh
nix develop
```

## Building

To build a beacon node you can use:
```sh
nix build '.#beacon_node'
```

It can be also done without even cloning the repo:
```sh
nix build 'github:status-im/nimbus-eth2'
```

>:warning: For Nix versions below `2.27` you will need to add `?submodules=1` to URL.

## Running

```sh
nix run 'github:status-im/nimbus-eth2'
```
