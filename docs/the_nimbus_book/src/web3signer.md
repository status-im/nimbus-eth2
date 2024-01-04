# Web3Signer

[Web3Signer](https://docs.web3signer.consensys.io) is a remote signing server developed by Consensys.
It offers a [standardized REST API](https://consensys.github.io/web3signer/web3signer-eth2.html) allowing the Nimbus beacon node or validator client to operate without storing any validator keys locally.

You can instruct Nimbus to connect to a Web3Signer instance by supplying the `--web3-signer-url` command-line option. Since Nimbus obtains the list of validator keys automatically through the [`/api/v1/eth2/publicKeys`](https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Public-Key/operation/ETH2_LIST) Web3Signer API endpoint, no further configuration is required.

!!! info
    By default, the list of validators will be refreshed once per hour. You can change the number of seconds between two updates with the `--web3signer-update-interval` command-line option.

!!! tip
    You can use multiple Web3Signer instances by specifying the `--web3-signer-url` parameter multiple times.

Alternatively, if you prefer not to depend on the automatic validator discovery mechanism or wish to take advantage of the advanced configurations described below, you have the option to permanently add multiple remote validators to a particular Nimbus data directory. This can be accomplished in two ways:

**On-the-fly Addition**: Utilize the [`POST /eth/v1/remotekeys`](https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ImportRemoteKeys) request when the Keymanager API is enabled. This allows you to dynamically add and remove remote validators as needed.

**Manual Configuration**: You can manually create a remote keystore file within the [validators directory](./data-dir.md#secrets-and-validators) of the client. This configuration will be loaded during the next restart of the client. Here is an example `remote_keystore.json` file:

```
{
  "version": 3,
  "description": "This is simple remote keystore file",
  "type": "verifying-web3signer",
  "pubkey": "0x8107ff6a5cfd1993f0dc19a6a9ec7dc742a528dd6f2e3e10189a4a6fc489ae6c7ba9070ea4e2e328f0d20b91cc129733",
  "remote": "http://127.0.0.1:15052",
  "ignore_ssl_verification": true,
  "proven_block_properties": [
    { "path": ".execution_payload.fee_recipient" }
  ]
}
```

The fields have the following semantics:

1. `version` - A decimal version number of the keystore format. This should be the first field.
2. `description` - An optional description of the keystore that can be set to any value by the user.
3. `type` - The type of the remote signer. The currently supported values are `web3signer` and `verifying-web3signer` (see below). Future versions may also support the protocol used by the [Dirk](https://www.attestant.io/posts/introducing-dirk/) signer.
4. `pubkey` - The validator's public key encoded in hexadecimal form.
5. `remote` - An URL of a remote signing server.
6. `remotes` - A [distributed keystore](#distributed-keystores) configuration including two or more remote signing servers.
7. `ignore_ssl_verification` - An optional boolean flag allowing the use of self-signed certificates by the signing server.
8. `proven_block_properties` - When the `verifying-web3signer` type is used, this is a list of locations within the SSZ block body for which the block signing requests will contain additional Merkle proofs, allowing the signer to verify certain details about the signed blocks (e.g. the `fee_recipient` value).

!!! info
    The current version of the remote keystore format is `3` which adds support for the experimental [verifying web3signer setups](#verifying-web3signer).
    Version `2` introduced the support for distributed keystores.

## Distributed Keystores

!!! warn
    This functionality is not currently recommended for production use.
    All details described below are subject to change after a planned security audit of the implementation.
    Please refer to the [Nimbus SSV Roadmap](https://github.com/status-im/nimbus-eth2/issues/3416) for more details.

The distributed keystores offer a mechanism for spreading the work of signing validator messages over multiple signing servers in order to gain higher resilience (safety, liveness, or both) when compared to running a validator client on a single machine.
When properly deployed, they can ensure that the validator key cannot be leaked to unauthorized third parties even when they have physical access to the machines where the signers are running.
Furthermore, the scheme supports M-out-of-N threshold signing configurations that can remain active even when some of the signing servers are taken offline.
For more information, please refer to the [Distributed Validator Specification](https://github.com/ethereum/distributed-validator-specs) published by the EF.

Currently, the distributed keystore support allows pairing a single Nimbus instance with multiple Web3Signer servers.
Future versions may allow creating a highly available cluster of Nimbus instances that mutually act as signers for each other.
Please refer to the [Nimbus SSV Roadmap](https://github.com/status-im/nimbus-eth2/issues/3416) for more details.

You can migrate any existing validator to a distributed keystore by splitting the key in multiple shares through the `ncli_split_keystore` program.

!!! info
    Since this is a preview feature, the `ncli_split_keystore` program is currently available only when compiling from source.
    To build it, clone the [nimbus-eth2 repository](https://github.com/status-im/nimbus-eth2) and run the `make ncli_split_keystore` command within its root.
    The resulting binary will be placed in the `build` folder sub-directory.

Here is an example invocation of the command:

```
build/ncli_split_keystore \
    --data-dir=$NIMBUS_DATA_DIR \
    --key=$VALIDATOR_PUBLIC_KEY \
    --threshold=2 \
    --remote-signer=http://signer-1-url \
    --remote-signer=http://signer-2-url \
    --remote-signer=http://signer-3-url \
    --out-dir=$OUT_DIR
```

The specified output directory will contain the following files:

```
$OUT_DIR/$VALIDATOR_PUBLIC_KEY/remote_keystore.json
$OUT_DIR/shares/secrets/1/$SHARE_1_PUBLIC_KEY
$OUT_DIR/shares/secrets/2/$SHARE_2_PUBLIC_KEY
$OUT_DIR/shares/secrets/3/$SHARE_3_PUBLIC_KEY
$OUT_DIR/shares/validators/1/$SHARE_1_PUBLIC_KEY/keystore.json
$OUT_DIR/shares/validators/2/$SHARE_2_PUBLIC_KEY/keystore.json
$OUT_DIR/shares/validators/3/$SHARE_3_PUBLIC_KEY/keystore.json
```

The keystores under the created `shares` directory must be moved to the server where the respective remote signer will be running, while the directory containing the `remote_keystore.json` file must be placed in the validators directory of the Nimbus.

The specified `threshold` value specifies the minimum number of signers that must remain online in order to create a signature.
Naturally, this value must be lower than the total number of specified remote signers.

If you are already using a threshold signing setup (e.g. based on Vouch and Dirk), you can migrate your partial keystores to any Web3Signer-compatible server and then manually create the `remote_keystore.json` file which must have the following structure:

```
{
  "version": 3,
  "pubkey": "0x8107ff6a5cfd1993f0dc19a6a9ec7dc742a528dd6f2e3e10189a4a6fc489ae6c7ba9070ea4e2e328f0d20b91cc129733",
  "remotes": [
    {
      "url": "http://signer-1-url",
      "id": 1,
      "pubkey": "83b26b1466f001d723e516b9a4f2ca13c01d9541b17a51a62ee8651d223dcc2dead9ce212e499815f43f7f96dddd4f5a"
    },
    {
      "url": "http://signer-2-url",
      "id": 2,
      "pubkey": "897727ba999519a55ac96b617a39cbba543fcd061a99fa4bcac8340dd19126a1130a8b6c2574add4debd4ec4c0c29faf"
    },
    {
      "url": "http://signer-3-url",
      "id": 3,
  `   "pubkey": "a68f3ac58974d993908a2e5796d04222411bcdfbb7e5b8c7a10df6717792f9b968772495c554d1b508d4a738014c49b4"
    }
  ],
  "threshold": 2,
  "type": "web3signer"
}
```

## Verifying Web3Signer

!!! warn
    This functionality is currently considered experimental.
    The described implementation may be incomplete and is subject to change in future releases.

The verifying Web3Signer is an experimental extension to the [Web3Signer protocol](https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing/operation/ETH2_SIGN) which allows the remote signer to verify certain details of the signed blocks before creating a signature (for example, the signer may require the signed block to have a particular fee recipient value).

To enable this use case, the `BLOCK_V2` request type of the `/api/v1/eth2/sign/{identifier}` endpoint is extended with an additional array field named `proofs`. The array consists of objects with the properties `index`, `proof` and `value`, where `index` is an arbitrary [generalized index](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/ssz/merkle-proofs.md#generalized-merkle-tree-index) of any property nested under the block body and `proof` is its corresponding Merkle proof against the block body root included in the request. The `value` property is optional and it is included only when the SSZ hash of the field included in the Merkle proof doesn't match its value.

Since the generalized index of a particular field may change in a hard-fork, in the remote keystore format the proven fields are usually specified by their name:

```
{
  "version": 3,
  "description": "This is simple remote keystore file",
  "type": "verifying-web3signer",
  "pubkey": "0x8107ff6a5cfd1993f0dc19a6a9ec7dc742a528dd6f2e3e10189a4a6fc489ae6c7ba9070ea4e2e328f0d20b91cc129733",
  "remote": "http://127.0.0.1:15052",
  "ignore_ssl_verification": true,
  "proven_block_properties": [
    { "path": ".execution_payload.fee_recipient" },
    { "path": ".graffiti" }
  ]
}
```

Nimbus automatically computes the generalized index depending on the currently active fork.
The remote signer is expected to verify the incoming Merkle proof through the standardized [is_valid_merkle_branch](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_valid_merkle_branch) function by utilizing a similar automatic mapping mechanism for the generalized index.

You can instruct Nimbus to use the verifying Web3Signer protocol by either supplying the `--verifying-web3-signer` command-line option or by creating a remote keystore file in the format described above. You can use the command-line option `--proven-block-property` once or multiple times to enumerate the properties of the block for which Merkle proofs will be supplied.
