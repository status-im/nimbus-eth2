# Web3Signer

[Web3Signer](https://docs.web3signer.consensys.net/en/latest/) is a remote signing server developed by Consensys. It offers a [standardized REST API](https://consensys.github.io/web3signer/web3signer-eth2.html) allowing the Nimbus beacon node or validator client to operate without storing any validator keys locally.

Remote validators can be permanently added to a Nimbus installation (or more precisely to a particular data directory) either on-the-fly through the [`POST /eth/v1/remotekeys`](https://ethereum.github.io/keymanager-APIs/#/Remote%20Key%20Manager/ImportRemoteKeys) request when the [Keymanager API](./keymanager-api.md) is enabled or by manually creating a remote keystore file within the validators directory of the client which will be loaded upon the next restart. The validators directory can be specified through the `--validators-dir` command-line parameter. The default value is `$DATA_DIR/validators` where $DATA_DIR is the directory specified through the `--data-dir` parameter.

Here is an example `remote_keystore.json` file:

```
{
  "version": 1,
  "description": "This is simple remote keystore file",
  "type": "web3signer",
  "pubkey": "0x8107ff6a5cfd1993f0dc19a6a9ec7dc742a528dd6f2e3e10189a4a6fc489ae6c7ba9070ea4e2e328f0d20b91cc129733",
  "remote": "http://127.0.0.1:15052",
  "ignore_ssl_verification": true
}
```

The fields have the following semantics:

1. `version` - an optional decimal version number of the keystore format. This should be the first field.
2. `description` - an optional description of the keystore that can be set to any value by the user.
3. `type` - an optional (by default `web3signer`) type of the remote signer. Right now only `web3signer` value is supported, but future versions may also support the protocol used by the [Dirk](https://www.attestant.io/posts/introducing-dirk/) signer.
4. `pubkey` - The validator's public key encoded in hexadecimal form (Required).
5. `remote` - The URL of the signing server (Required).
6. `ignore_ssl_verification` - an optional boolean flag allowing the user of self-signed certificates by the signing server.

Alternatively, version "2" of the format which is described below can be used for both regular remote keystores and distributed keystores.

## Distributed Keystores

> ⚠️  This functionality is not currently recommended for production use. All details described below are subject to change after a planned security audit of the implementation. Please refer to the [Nimbus SSV Roadmap](https://github.com/status-im/nimbus-eth2/issues/3416) for more details.

The distributed keystores offer a mechanism for spreading the work of signing validator messages over multiple signing servers in order to gain higher resilience (safety, liveness, or both) when compared to running a validator client on a single machine. When properly deployed, they can ensure that the validator key cannot be leaked to unauthorized third parties even when they have physical access to the machines where the signers are running. Furthermore, the scheme supports M-out-of-N threshold signing configurations that can provide 100% uptime guarantee even when some of the signing servers are taken offline. For more information, please refer to the [Distributed Validator Specification](https://github.com/ethereum/distributed-validator-specs) published by the EF.

Currently, the distributed keystore support allows pairing a single Nimbus instance with multiple Web3Signer servers. Future versions may allow creating a highly available cluster of Nimbus instances that mutually act as signers for each other. Please refer to the [Nimbus SSV Roadmap](https://github.com/status-im/nimbus-eth2/issues/3416) for more details.

You can migrate any existing validator to a distributed keystore by splitting the key in multiple shares through the `ncli_split_keystore` program.

> Since this is a preview feature, the `ncli_split_keystore` program is currently available only when compiling from source. To build it, clone the [nimbus-eth2 repository](https://github.com/status-im/nimbus-eth2) and run the `make ncli_split_keystore` command within its root. The resulting binary will be placed in the `build` folder sub-directory.

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

The specified `threshold` value specifies the minimum number of signers that must remain online in order to create a signature. Naturally, this value must be lower than the total number of specified remote signers.

If you are already using a threshold signing setup (e.g. based on Vouch and Dirk), you can migrate your partial keystores to any Web3Signer-compatible server and then manually create the `remote_keystore.json` file which must have the following structure:


```
{
  "version": 2,
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
      "pubkey": "a68f3ac58974d993908a2e5796d04222411bcdfbb7e5b8c7a10df6717792f9b968772495c554d1b508d4a738014c49b4"
    }
  ],
  "threshold": 2,
  "type": "web3signer"
}
```
