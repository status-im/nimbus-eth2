---
title: "Command Line Interface (CLI)"
code_owner: "Zahary Karadjov (zah)"
round: "Audit round 3"
category: "Validator Core Audit"
repositories: "nim-beacon-chain, nim-confutils"
---

## Goals

- Ensure that the CLI can handle malicious inputs (overflow, unicode, invalid characters, ...)
- Prevent users from shooting themselves in the foot:
    - Avoid losing data
    - Avoid losing funds/secrets (overlap with NCC work on secrets acknowledged, more eyes on this critical part is welcome)
    - Clear instructions:
        - The book [https://status-im.github.io/nim-beacon-chain/](https://status-im.github.io/nim-beacon-chain/)
        - Audit freeze: [https://github.com/status-im/nim-beacon-chain/tree/nbc-audit-2020-1/docs/the_nimbus_book/src](https://github.com/status-im/nim-beacon-chain/tree/nbc-audit-2020-1/docs/the_nimbus_book/src)
- With a focus on the workflow to stake ETH
    - See the book
    - [https://medalla.launchpad.ethereum.org/](https://medalla.launchpad.ethereum.org/)

## Code

- All conf options: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/beacon_chain/conf.nim)
- Makefile with preset build/run configuration: [https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/Makefile](https://github.com/status-im/nim-beacon-chain/blob/nbc-audit-2020-1/Makefile)

The key binaries with a CLI are:

- beacon_node.nim which is configured by the BeaconConf type
and can be compiled with `make beacon_node`
- validator_client.nim which is configured by `make validator_client`
- deposit_contract.nim which allows to make a ETH1 deposit

## Secret keys

TODO

- Address with Goerli ETH to test the deposit contract and ETH2 keystore generation
- ETH2 validator enabled on Medalla to test the beacon_node / validator_client

## Related audit reports

Trail of bits audit of the Ethereum Foundation deposit contract:

- [https://github.com/ethereum/eth2.0-deposit-cli/issues?q=is%3Aissue+is%3Aopen+ToB+Audit](https://github.com/ethereum/eth2.0-deposit-cli/issues?q=is%3Aissue+is%3Aopen+ToB+Audit)

----------------------------------------------------------------

https://github.com/status-im/nim-beacon-chain/issues/1320 ← also relevant for walletfile generation (even though the file is encrypted and usually in an ACL protected subpath (userdir); but its world readable + may leak info about wallets)

https://github.com/status-im/nim-beacon-chain/issues/1687
