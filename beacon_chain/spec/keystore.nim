# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  math, strutils,
  json_serialization,
  eth/keyfile/uuid,
  stew/[results, byteutils],
  nimcrypto/[sha2, rijndael, pbkdf2, bcmode, hash, sysrand],
  ./crypto

export results

{.push raises: [Defect].}

type
  ChecksumParams = object

  Checksum = object
    function: string
    params: ChecksumParams
    message: string

  CipherParams = object
    iv: string

  Cipher = object
    function: string
    params: CipherParams
    message: string

  ScryptParams = object
    dklen: int
    n, p, r: int
    salt: string

  Pbkdf2Params = object
    dklen: int
    c: int
    prf: string
    salt: string

  KdfKind* = enum
    kdfPbkdf2 = "pbkdf2"
    kdfScrypt = "scrypt"

  Kdf = object
    case function: KdfKind
    of kdfPbkdf2:
      pbkdf2Params {.serializedFieldName("params").}: Pbkdf2Params
    of kdfScrypt:
      scryptParams {.serializedFieldName("params").}: ScryptParams
    message: string

  Crypto = object
    kdf: Kdf
    checksum: Checksum
    cipher: Cipher

  Keystore = object
    crypto: Crypto
    pubkey: string
    path: string
    uuid: string
    version: int

  KsResult*[T] = Result[T, cstring]

const
  keyLen = 32

  scryptParams = ScryptParams(
    dklen: keyLen,
    n: 2^18,
    r: 1,
    p: 8
  )

  pbkdf2Params = Pbkdf2Params(
    dklen: keyLen,
    c: 2^18,
    prf: "hmac-sha256"
  )

proc shaChecksum(key, cipher: openarray[byte]): array[32, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(key)
  ctx.update(cipher)
  result = ctx.finish().data
  ctx.clear()

template hexToBytes(data, name: string): untyped =
  try:
    hexToSeqByte(data)
  except ValueError:
    return err "ks: failed to parse " & name

proc decryptKeystore*(json, passphrase: string): KsResult[seq[byte]] =
  let
    crypto =
      try:
        Json.decode(json, Keystore).crypto
      except Exception:
        return err "ks: failed to parse keystore"

    iv = hexToBytes(crypto.cipher.params.iv, "iv")
    cipherMsg = hexToBytes(crypto.cipher.message, "cipher")
    checksumMsg = hexToBytes(crypto.checksum.message, "checksum")

  var decKey: seq[byte]

  case crypto.kdf.function
  of kdfPbkdf2:
    let salt = hexToBytes(crypto.kdf.pbkdf2Params.salt, "salt")
    decKey = sha256.pbkdf2(passphrase, salt,
                           crypto.kdf.pbkdf2Params.c,
                           crypto.kdf.pbkdf2Params.dklen)
  of kdfScrypt:
    return err "ks: scrypt not supported"

  if decKey.len < keyLen:
    return err "ks: decryption key must be at least 32 bytes"

  if iv.len < aes128.sizeBlock:
    return err "ks: invalid iv"

  let sum = shaChecksum(decKey.toOpenArray(16, 31), cipherMsg)
  if sum != checksumMsg:
    return err "ks: invalid checksum"

  var
    aesCipher: CTR[aes128]
    secret = newSeq[byte](cipherMsg.len)

  aesCipher.init(decKey.toOpenArray(0, 15), iv)
  aesCipher.decrypt(cipherMsg, secret)
  aesCipher.clear()

  result = ok secret

proc encryptKeystore*(cipher: KdfKind;
                      secret: openarray[byte];
                      passphrase: string;
                      path="";
                      salt: openarray[byte] = @[];
                      iv: openarray[byte] = @[]): KsResult[string] =
  var
    kdf: Kdf
    decKey: seq[byte]
    aesCipher: CTR[aes128]
    aesIv = newSeq[byte](aes128.sizeBlock)
    kdfSalt = newSeq[byte](keyLen)
    cipherMsg = newSeq[byte](secret.len)

  if salt.len == keyLen:
    kdfSalt = @salt
  elif salt.len > 0:
    return err "ks: invalid salt length"
  elif randomBytes(kdfSalt) != keyLen:
    return err "ks: no random bytes for salt"

  if iv.len == aes128.sizeBlock:
    aesIv = @iv
  elif iv.len > 0:
    return err "ks: invalid iv length"
  elif randomBytes(aesIv) != aes128.sizeBlock:
    return err "ks: no random bytes for iv"

  case cipher
  of kdfPbkdf2:
    var params = pbkdf2Params
    params.salt = kdfSalt.toHex()
    kdf = Kdf(function: kdfPbkdf2, pbkdf2Params: params)

    decKey = sha256.pbkdf2(passphrase, params.salt, params.c, params.dklen)
  of kdfScrypt:
    return err "ks: scrypt not supported"

  aesCipher.init(decKey.toOpenArray(0, 15), aesIv)
  aesCipher.encrypt(secret, cipherMsg)
  aesCipher.clear()

  let
    sum = shaChecksum(decKey.toOpenArray(16, 31), cipherMsg)

    keystore = Keystore(
      crypto: Crypto(
        kdf: kdf,
        checksum: Checksum(
          function: "sha256",
          message: sum.toHex()
        ),
        cipher: Cipher(
          function: "aes-128-ctr",
          params: CipherParams(iv: aesIv.toHex()),
          message: cipherMsg.toHex()
        )
      ),
      pubkey: (? ValidatorPrivkey.fromRaw(secret)).toPubKey().toHex(),
      path: path,
      uuid: $(? uuidGenerate()),
      version: 4
    )

  try:
    result = ok keystore.toJson(pretty=true)
  except IOError:
    result = err "ks: json serialization error"
