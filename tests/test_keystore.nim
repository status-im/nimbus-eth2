# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[json, typetraits],
  unittest2,
  stew/byteutils, blscurve, json_serialization,
  libp2p/crypto/crypto as lcrypto,
  ../beacon_chain/spec/[crypto, keystore],
  ./testutil

from std/strutils import replace

func isEqual(a, b: ValidatorPrivKey): bool =
  # `==` on secret keys is not allowed
  let pa = cast[ptr UncheckedArray[byte]](a.unsafeAddr)
  let pb = cast[ptr UncheckedArray[byte]](b.unsafeAddr)
  result = true
  for i in 0 ..< sizeof(a):
    result = result and pa[i] == pb[i]

const
  scryptVector = """
  {
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

  scryptVector2 = """
  {
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
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/3141592653/589793238",
    "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
    "version": 4
  }"""

  pbkdf2Vector = """
  {
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

  pbkdf2Vector2 = """
  {
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
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/0/0",
    "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
    "version": 4
  }"""

  pbkdf2NetVector = """
  {
    "crypto":{
      "kdf":{
         "function":"pbkdf2",
         "params":{
            "dklen":32,
            "c":262144,
            "prf":"hmac-sha256",
            "salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
         },
         "message":""
      },
      "checksum":{
         "function":"sha256",
         "params":{

         },
         "message":"3aaebceb5e81cce464d62287414befaa03522eb8f56cad4296c0dc9301e5f091"
      },
      "cipher":{
         "function":"aes-128-ctr",
         "params":{
            "iv":"264daa3f303d7259501c93d997d84fe6"
         },
         "message":"c6e22dfed4aec458af6e46efff72937972a9360a8b4dc32c8c266de73a90b421d8892db3"
      }
    },
    "description":"PBKDF2 Network private key storage",
    "pubkey":"08021221031873e6f4e1bf837b93493d570653cb219743d4fab0ff468d4e005e1679730b0b",
    "uuid":"7a053160-1cdf-4faf-a2bb-331e1bc2eb5f",
    "version":1
  }"""

  scryptNetVector = """
  {
    "crypto":{
      "kdf":{
         "function":"scrypt",
         "params":{
            "dklen":32,
            "n":262144,
            "p":1,
            "r":8,
            "salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
         },
         "message":""
      },
      "checksum":{
         "function":"sha256",
         "params":{

         },
         "message":"9a7d03a3f2107a11b6e34a081fb13d551012ff081efb81fc94ec114381fa707f"
      },
      "cipher":{
         "function":"aes-128-ctr",
         "params":{
            "iv":"264daa3f303d7259501c93d997d84fe6"
         },
         "message":"0eac82f5a1bd53f81df688970ffeea8425ad7b8f877bcba5a74b87f090c340836cd52095"
      }
    },
    "description":"SCRYPT Network private key storage",
    "pubkey":"08021221031873e6f4e1bf837b93493d570653cb219743d4fab0ff468d4e005e1679730b0b",
    "uuid":"83d77fa3-86cb-466a-af11-eeb338b0e258",
    "version":1
  }"""

  prysmKeystore = """
  {
    "crypto": {
            "checksum": {
                    "function": "sha256",
                    "message": "54fc80f6d0676bdae7c968e0d462f90a4e3a028fc7669ef8527e2f74386c9b36",
                    "params": {}
            },
            "cipher": {
                    "function": "aes-128-ctr",
                    "message": "3c2540f69cbe7e66c0c4a6e416e99bf0d1056399c21b4c45552561da920871fa",
                    "params": {
                            "iv": "98a15bd46d258aceecaeeab25bddf5e2"
                    }
            },
            "kdf": {
                    "function": "pbkdf2",
                    "message": "",
                    "params": {
                            "c": 262144,
                            "dklen": 32,
                            "prf": "hmac-sha256",
                            "salt": "c0abbbbda36e588824865a71b5b34d5a95335fe1077c286d4e9c844f7193c62b"
                    }
            }
    },
    "uuid": "39796eb1-2e43-4353-9f13-5211c7ddc58c",
    "pubkey": "8ed78a5495b54d5b6cc8bf170534ecb633b9694fba121ca680744fa9633f1b67cc77c045f88a6f97be781fe6c2867646",
    "version": 4,
    "name": "keystore",
    "path": ""
  }
  """

  password = string.fromBytes hexToSeqByte("7465737470617373776f7264f09f9491")
  secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  secretNetBytes = hexToSeqByte "08021220fe442379443d6e2d7d75d3a58f96fbb35f0a9c7217796825fc9040e3b89c5736"
  salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
  iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"

let
  rng = HmacDrbgContext.new()

suite "KeyStorage testing suite":
  setup:
    let secret = ValidatorPrivKey.fromRaw(secretBytes).get
    let nsecret = init(lcrypto.PrivateKey, secretNetBytes).get

  test "Load Prysm keystore":
    let keystore = parseKeystore(prysmKeystore)
    check keystore.uuid == "39796eb1-2e43-4353-9f13-5211c7ddc58c"

  test "[PBKDF2] Keystore decryption":
    let
      keystore = parseKeystore(pbkdf2Vector)
      decrypt = decryptKeystore(keystore, KeystorePass.init password)

    check decrypt.isOk
    check secret.isEqual(decrypt.get())

  test "[PBKDF2] Keystore decryption (requireAllFields, allowUnknownFields)":
    let
      keystore = parseKeystore(pbkdf2Vector2)
      decrypt = decryptKeystore(keystore, KeystorePass.init password)

    check decrypt.isOk
    check secret.isEqual(decrypt.get())

  test "[SCRYPT] Keystore decryption":
    let
      keystore = parseKeystore(scryptVector)
      decrypt = decryptKeystore(keystore, KeystorePass.init password)

    check decrypt.isOk
    check secret.isEqual(decrypt.get())

  test "[SCRYPT] Keystore decryption (requireAllFields, allowUnknownFields)":
    let
      keystore = parseKeystore(pbkdf2Vector2)
      decrypt = decryptKeystore(keystore, KeystorePass.init password)

    check decrypt.isOk
    check secret.isEqual(decrypt.get())

  test "[PBKDF2] Network Keystore decryption":
    let
      keystore = parseNetKeystore(pbkdf2NetVector)
      decrypt = decryptNetKeystore(keystore, KeystorePass.init password)

    check decrypt.isOk
    check nsecret == decrypt.get()

  test "[SCRYPT] Network Keystore decryption":
    let
      keystore = parseNetKeystore(scryptNetVector)
      decrypt = decryptNetKeystore(keystore, KeystorePass.init password)

    check decrypt.isOk
    check nsecret == decrypt.get()

  test "[PBKDF2] Keystore encryption":
    let keystore = createKeystore(kdfPbkdf2, rng[], secret,
                                  KeystorePass.init password,
                                  salt=salt, iv=iv,
                                  description = "This is a test keystore that uses PBKDF2 to secure the secret.",
                                  path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))
    var
      encryptJson = parseJson Json.encode(keystore)
      pbkdf2Json = parseJson(pbkdf2Vector)
    encryptJson{"uuid"} = %""
    pbkdf2Json{"uuid"} = %""

    check encryptJson == pbkdf2Json

  test "[PBKDF2] Network Keystore encryption":
    let nkeystore = createNetKeystore(kdfPbkdf2, rng[], nsecret,
                                      KeystorePass.init password,
                                      salt = salt, iv = iv,
                                      description =
                                        "PBKDF2 Network private key storage")
    var
      encryptJson = parseJson Json.encode(nkeystore)
      pbkdf2Json = parseJson(pbkdf2NetVector)
    encryptJson{"uuid"} = %""
    pbkdf2Json{"uuid"} = %""
    check encryptJson == pbkdf2Json

  test "[SCRYPT] Keystore encryption":
    let keystore = createKeystore(kdfScrypt, rng[], secret,
                                  KeystorePass.init password,
                                  salt=salt, iv=iv,
                                  description = "This is a test keystore that uses scrypt to secure the secret.",
                                  path = validateKeyPath("m/12381/60/3141592653/589793238").expect("Valid keypath"))
    var
      encryptJson = parseJson Json.encode(keystore)
      scryptJson = parseJson(scryptVector)
    encryptJson{"uuid"} = %""
    scryptJson{"uuid"} = %""

    check encryptJson == scryptJson

  test "[SCRYPT] Network Keystore encryption":
    let nkeystore = createNetKeystore(kdfScrypt, rng[], nsecret,
                                      KeystorePass.init password,
                                      salt = salt, iv = iv,
                                      description =
                                        "SCRYPT Network private key storage")
    var
      encryptJson = parseJson Json.encode(nkeystore)
      pbkdf2Json = parseJson(scryptNetVector)
    encryptJson{"uuid"} = %""
    pbkdf2Json{"uuid"} = %""
    check encryptJson == pbkdf2Json

  test "Pbkdf2 errors":
    expect Defect:
      echo createKeystore(kdfPbkdf2, rng[], secret, salt = [byte 1])

    expect Defect:
      echo createKeystore(kdfPbkdf2, rng[], secret, iv = [byte 1])

    check decryptKeystore(JsonString pbkdf2Vector,
                          KeystorePass.init "wrong pass").isErr

    check decryptKeystore(JsonString pbkdf2Vector,
                          KeystorePass.init "").isErr

    check decryptKeystore(JsonString "{\"a\": 0}",
                          KeystorePass.init "").isErr

    check decryptKeystore(JsonString "",
                          KeystorePass.init "").isErr

    check decryptKeystore(JsonString "{}",
                          KeystorePass.init "").isErr

    template checkVariant(remove): untyped =
      check decryptKeystore(JsonString pbkdf2Vector.replace(remove, "1234"),
                            KeystorePass.init password).isErr

    checkVariant "f876" # salt
    checkVariant "75ea" # checksum
    checkVariant "b722" # cipher

    let badKdf = parseJson(pbkdf2Vector)
    badKdf{"crypto", "kdf", "function"} = %"invalid"

    check decryptKeystore(JsonString $badKdf,
                          KeystorePass.init password).isErr

suite "eth2.0-deposits-cli compatibility":
  test "restoring mnemonic without password":
    let mnemonic = Mnemonic "camera dad smile sail injury warfare grid kiwi report minute fold slot before stem firm wet vague shove version medal one alley vibrant mushroom"
    let seed = getSeed(mnemonic, KeystorePass.init "")
    check byteutils.toHex(distinctBase seed) == "60043d6e1efe0eea2ef1c8e7d4bb2d79cb27d3403e992b6058998c27c373cfb6fe047b11405360bb224803726fd6b0ee9e3335ae7d9032e6cb49baf08697cf2a"

    let masterKey = deriveMasterKey(seed)
    check masterKey.toHex == "54aea900840c22ee821ca4f67ba57392d7c3e3d4fc54a6343940c12404226eb7"

    let
      v1SK = deriveChildKey(masterKey, makeKeyPath(0, signingKeyKind))
      v1WK = deriveChildKey(masterKey, makeKeyPath(0, withdrawalKeyKind))

      v2SK = deriveChildKey(masterKey, makeKeyPath(1, signingKeyKind))
      v2WK = deriveChildKey(masterKey, makeKeyPath(1, withdrawalKeyKind))

      v3SK = deriveChildKey(masterKey, makeKeyPath(2, signingKeyKind))
      v3WK = deriveChildKey(masterKey, makeKeyPath(2, withdrawalKeyKind))

    check:
      v1SK.toHex == "261610f7cb44fd17da74b1d0018db0bf311cfb0d30fd6bc7879d3db022a1ac7d"
      v1WK.toHex == "0924b5928633a6712a392a8172bd0b3ce6b591491ed4b448d51b460d293258e1"

      v2SK.toHex == "3ee523f969f9e0eed10ec62a4b816d94e28947fc1c55ba791555b83baef23b43"
      v2WK.toHex == "4925c51f41cd275c70ec878a35a6640e69d1d9360f3dcf6400692a670bda27c2"

      v3SK.toHex == "05935491479f8ad8887c4bf64e69fddf9c2d42848bb8a98170a5fe41e94c4122"
      v3WK.toHex == "56b158b3b170e9c339b94b895afc28964a0b6d7a0809a39b558ca8b6688487cd"

  test "restoring mnemonic with password":
    let mnemonic = Mnemonic "swear umbrella lesson couch void gentle rocket valley distance match floor rocket flag solve muscle common modify target city youth pottery predict flip ghost"
    let seed = getSeed(mnemonic, KeystorePass.init "abracadabra!@#$%^7890")
    check byteutils.toHex(distinctBase seed) == "f129c3ac003a07e54974d8dbeb08d20c2343fc516e0e3704570c500a4b6ed98bad2e6fec6a3b9a88076c17feaa0d01163855578cb08bae53860d0ae2558cf03e"

    let
      masterKey = deriveMasterKey(seed)

      v1SK = deriveChildKey(masterKey, makeKeyPath(0, signingKeyKind))
      v1WK = deriveChildKey(masterKey, makeKeyPath(0, withdrawalKeyKind))

      v2SK = deriveChildKey(masterKey, makeKeyPath(1, signingKeyKind))
      v2WK = deriveChildKey(masterKey, makeKeyPath(1, withdrawalKeyKind))

      v3SK = deriveChildKey(masterKey, makeKeyPath(2, signingKeyKind))
      v3WK = deriveChildKey(masterKey, makeKeyPath(2, withdrawalKeyKind))

    check:
      v1SK.toHex == "16059302897bc6ecdb9cdac9bb27f34cc996e04b75143c73742aa5975bfaeae7"
      v1WK.toHex == "1c28b8e41e5cb2f983780eabb77c927e804d1f7aaffcaaf5593538885a658e8a"

      v2SK.toHex == "49a5fa9536ebb96253d420a4a9e9f054dc872d2a49884d46995b39b8147fd5e3"
      v2WK.toHex == "70068f12a854370d18284884df62d3911af2f85d0be29cb071ec78c6ec564695"

      v3SK.toHex == "1445cec3861d7cbf80e409d79aeee131622dcb0c815ff97ceab2515e14c41a1a"
      v3WK.toHex == "1ccd5dce4c842bd3f65bbd59a382662e689fcf01ddc39aaaf2dcc7d073f11a93"
