# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/typetraits,
  unittest2, json_serialization,
  blscurve,
  ../beacon_chain/spec/[crypto, keystore],
  ./testutil

template parse(keystore: string): auto =
  try:
    parseRemoteKeystore(keystore)
  except SerializationError as err:
    checkpoint "Serialization Error: " & err.formatMsg("<keystore>")
    raise err

suite "Remove keystore testing suite":
  test "vesion 1" :
    for version in [1, 2]:
      let remoteKeyStores = """{
        "version": """ & $version & """,
        "pubkey": "0x8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c",
        "remote": "http://127.0.0.1:6000"
      }"""
      let keystore = parse(remoteKeyStores)
      check keystore.pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
      check keystore.remotes.len == 1
      check $keystore.remotes[0].url == "http://127.0.0.1:6000"
      check keystore.remotes[0].id == 0
      check keystore.remotes[0].pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"

    for version in [1, 3]:
      let remoteKeyStores = """{
        "version": """ & $version & """,
        "type": "web3signer",
        "pubkey": "0x8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c",
        "remote": "http://127.0.0.1:6000"
      }"""
      let keystore = parse(remoteKeyStores)
      check keystore.pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
      check keystore.remotes.len == 1
      check $keystore.remotes[0].url == "http://127.0.0.1:6000"
      check keystore.remotes[0].id == 0
      check keystore.remotes[0].pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"

  test "Single remote":
    for version in [2, 3]:
      let remoteKeyStores = """{
        "version": """ & $version & """,
        "type": "web3signer",
        "pubkey": "0x8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c",
        "remotes": [
          {
            "url": "http://127.0.0.1:6000",
            "pubkey": "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
          }
        ]
      }"""
      let keystore = parse(remoteKeyStores)
      check keystore.pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
      check keystore.remotes.len == 1
      check $keystore.remotes[0].url == "http://127.0.0.1:6000"
      check keystore.remotes[0].id == 0
      check keystore.remotes[0].pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"

  test "Many remotes" :
    for version in [2, 3]:
      let remoteKeyStores = """{
        "version": """ & $version & """,
        "type": "web3signer",
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
        "threshold": 2
      }"""
      let keystore = parse(remoteKeyStores)
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

  test "Verifying Signer / Single remote":
    for version in [3]:
      let remoteKeyStores = """{
        "version": """ & $version & """,
        "type": "verifying-web3signer",
        "proven_block_properties": [
          {
            "path": ".execution_payload.fee_recipient"
          }
        ],
        "pubkey": "0x8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c",
        "remotes": [
          {
            "url": "http://127.0.0.1:6000",
            "pubkey": "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
          }
        ]
      }"""
      let keystore = parse(remoteKeyStores)
      check keystore.pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
      check keystore.remotes.len == 1
      check $keystore.remotes[0].url == "http://127.0.0.1:6000"
      check keystore.remotes[0].id == 0
      check keystore.remotes[0].pubkey.toHex == "8b9c875fbe539c6429c4fc304675062579ce47fb6b2ac6b6a1ba1188ca123a80affbfe381dbbc8e7f2437709a4c3325c"
      check keystore.provenBlockProperties.len == 1
      check keystore.provenBlockProperties[0].capellaIndex == some GeneralizedIndex(401)
      check keystore.provenBlockProperties[0].denebIndex == some GeneralizedIndex(801)

  test "Verifying Signer / Many remotes":
    for version in [3]:
      let remoteKeyStores = """{
        "version": """ & $version & """,
        "type": "verifying-web3signer",
        "proven_block_properties": [
          {
            "description": "The fee recipient field of the execution payload",
            "path": ".execution_payload.fee_recipient"
          }
        ],
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
        "threshold": 2
      }"""
      let keystore = parse(remoteKeyStores)
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
      check keystore.provenBlockProperties.len == 1
      check keystore.provenBlockProperties[0].capellaIndex == some GeneralizedIndex(401)
      check keystore.provenBlockProperties[0].denebIndex == some GeneralizedIndex(801)