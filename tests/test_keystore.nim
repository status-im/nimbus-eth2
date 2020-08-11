# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  json, unittest,
  stew/byteutils, blscurve, eth/keys, json_serialization,
  ../beacon_chain/spec/[crypto, keystore],
  ./testutil

from strutils import replace

func isEqual*(a, b: ValidatorPrivKey): bool =
  # `==` on secret keys is not allowed
  let pa = cast[ptr UncheckedArray[byte]](a.unsafeAddr)
  let pb = cast[ptr UncheckedArray[byte]](b.unsafeAddr)
  result = true
  for i in 0 ..< sizeof(a):
    result = result and pa[i] == pdec[i]

const
  scryptVector = """{
    "crypto": {
        "kdf": {
            "function": "scrypt",
            "params": {
                "dklen": 32,
                "n": 262144,
                "p": 1,
                "r": 8,
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
        },
        "cipher": {
            "function": "aes-128-ctr",
            "params": {
                "iv": "264daa3f303d7259501c93d997d84fe6"
            },
            "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
        }
    },
    "description": "This is a test keystore that uses scrypt to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/3141592653/589793238",
    "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
    "version": 4
}"""

  pbkdf2Vector = """{
    "crypto": {
        "kdf": {
            "function": "pbkdf2",
            "params": {
                "dklen": 32,
                "c": 262144,
                "prf": "hmac-sha256",
                "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
            },
            "message": ""
        },
        "checksum": {
            "function": "sha256",
            "params": {},
            "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
        },
        "cipher": {
            "function": "aes-128-ctr",
            "params": {
                "iv": "264daa3f303d7259501c93d997d84fe6"
            },
            "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
        }
    },
    "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/0/0",
    "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
    "version": 4
}"""

  password = string.fromBytes hexToSeqByte("7465737470617373776f7264f09f9491")
  secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

  salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
  iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"

let
  rng = newRng()

suiteReport "Keystore":
  setup:
    let secret = ValidatorPrivKey.fromRaw(secretBytes).get

  timedTest "Pbkdf2 decryption":
    let
      keystore = Json.decode(pbkdf2Vector, Keystore)
      decrypt = decryptKeystore(keystore, KeystorePass password)

    check decrypt.isOk
    check secret.isEqual(decrypt.get())

  timedTest "Scrypt decryption":
    let
      keystore = Json.decode(scryptVector, Keystore)
      decrypt = decryptKeystore(keystore, KeystorePass password)

    check decrypt.isOk
    check secret.isEqual(decrypt.get())

  timedTest "Pbkdf2 encryption":
    let keystore = createKeystore(kdfPbkdf2, rng[], secret,
                                  KeystorePass password,
                                  salt=salt, iv=iv,
                                  description = "This is a test keystore that uses PBKDF2 to secure the secret.",
                                  path = validateKeyPath "m/12381/60/0/0")
    var
      encryptJson = parseJson Json.encode(keystore)
      pbkdf2Json = parseJson(pbkdf2Vector)
    encryptJson{"uuid"} = %""
    pbkdf2Json{"uuid"} = %""

    check encryptJson == pbkdf2Json

  timedTest "Scrypt encryption":
    let keystore = createKeystore(kdfScrypt, rng[], secret,
                                  KeystorePass password,
                                  salt=salt, iv=iv,
                                  description = "This is a test keystore that uses scrypt to secure the secret.",
                                  path = validateKeyPath "m/12381/60/3141592653/589793238")
    var
      encryptJson = parseJson Json.encode(keystore)
      scryptJson = parseJson(scryptVector)
    encryptJson{"uuid"} = %""
    scryptJson{"uuid"} = %""

    check encryptJson == scryptJson

  timedTest "Pbkdf2 errors":
    expect Defect:
      echo createKeystore(kdfPbkdf2, rng[], secret, salt = [byte 1])

    expect Defect:
      echo createKeystore(kdfPbkdf2, rng[], secret, iv = [byte 1])

    check decryptKeystore(JsonString pbkdf2Vector,
                          KeystorePass "wrong pass").isErr

    check decryptKeystore(JsonString pbkdf2Vector,
                          KeystorePass "").isErr

    check decryptKeystore(JsonString "{\"a\": 0}",
                          KeystorePass "").isErr

    check decryptKeystore(JsonString "",
                          KeystorePass "").isErr

    template checkVariant(remove): untyped =
      check decryptKeystore(JsonString pbkdf2Vector.replace(remove, "1234"),
                            KeystorePass password).isErr

    checkVariant "f876" # salt
    checkVariant "75ea" # checksum
    checkVariant "b722" # cipher

    var badKdf = parseJson(pbkdf2Vector)
    badKdf{"crypto", "kdf", "function"} = %"invalid"

    check decryptKeystore(JsonString $badKdf,
                          KeystorePass password).iserr
