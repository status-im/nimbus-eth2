{.used.}

import
  std/[json, typetraits],
  unittest2, stew/byteutils, json_serialization,
  blscurve, eth/keys, libp2p/crypto/crypto as lcrypto,
  nimcrypto/utils as ncrutils,
  ../beacon_chain/spec/[crypto, keystore],
  ./testutil

suite "Remove keystore testing suite":
  test "vesion 1" :
    let remoteKeyStores = """{
      "version": 1,
      "pubkey": "0x8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c",
      "remote": "http://127.0.0.1:6000",
      "type": "web3signer"
    }"""
    let keystore = Json.decode(remoteKeyStores, RemoteKeystore)
    check keystore.pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
    check keystore.remotes.len == 1
    check $keystore.remotes[0].url == "http://127.0.0.1:6000"
    check keystore.remotes[0].id == 0
    check keystore.remotes[0].pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"

  test "vesion 2 single remote":
    let remoteKeyStores = """{
      "version": 2,
      "pubkey": "0x8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c",
      "remotes": [
        {
          "url": "http://127.0.0.1:6000",
          "pubkey": "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
        }
      ],
      "type": "web3signer"
    }"""
    let keystore = Json.decode(remoteKeyStores, RemoteKeystore)
    check keystore.pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
    check keystore.remotes.len == 1
    check $keystore.remotes[0].url == "http://127.0.0.1:6000"
    check keystore.remotes[0].id == 0
    check keystore.remotes[0].pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"

  test "vesion 2 many remotes" :
    let remoteKeyStores = """{
      "version": 2,
      "pubkey": "0x8ebc7291df2a671326de83471a4feeb759cc842caa59aa92065e3508baa7e50513bc49a79ff4387c8ef747764f364b6f",
      "remotes": [
        {
          "url": "http://127.0.0.1:6000",
          "id": 1,
          "pubkey": "95313b967bcd761175dbc2a5685c16b1a73000e66f9622eca080cb0428dd3db61f7377b32b1fd27f3bdbdf2b554e7f87"
        },
        {
          "url": "http://127.0.0.1:6001",
          "id": 2,
          "pubkey": "8b8c115d19a9bdacfc7af9c8e8fc1353af54b63b0e772a641499cac9b6ea5cb1b3479cfa52ebc98ba5afe07a06c06238"
        },
        {
          "url": "http://127.0.0.1:6002",
          "id": 3,
          "pubkey": "8f5f9e305e7fcbde94182747f5ecec573d1786e8320a920347a74c0ff5e70f12ca22607c98fdc8dbe71161db59e0ac9d"
        }
      ],
      "threshold": 2,
      "type": "web3signer"
    }"""
    let keystore = Json.decode(remoteKeyStores, RemoteKeystore)
    check keystore.pubkey.toHex == "8ebc7291df2a671326de83471a4feeb759cc842caa59aa92065e3508baa7e50513bc49a79ff4387c8ef747764f364b6f"
    check keystore.remotes.len == 3
    check $keystore.remotes[0].url == "http://127.0.0.1:6000"
    check $keystore.remotes[1].url == "http://127.0.0.1:6001"
    check $keystore.remotes[2].url == "http://127.0.0.1:6002"
    check keystore.remotes[0].id == 1
    check keystore.remotes[1].id == 2
    check keystore.remotes[2].id == 3
    check keystore.remotes[0].pubkey.toHex == "95313b967bcd761175dbc2a5685c16b1a73000e66f9622eca080cb0428dd3db61f7377b32b1fd27f3bdbdf2b554e7f87"
    check keystore.remotes[1].pubkey.toHex == "8b8c115d19a9bdacfc7af9c8e8fc1353af54b63b0e772a641499cac9b6ea5cb1b3479cfa52ebc98ba5afe07a06c06238"
    check keystore.remotes[2].pubkey.toHex == "8f5f9e305e7fcbde94182747f5ecec573d1786e8320a920347a74c0ff5e70f12ca22607c98fdc8dbe71161db59e0ac9d"
    check keystore.threshold == 2
