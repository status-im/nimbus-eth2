# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  json, math, strutils,
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

  KdfScrypt* = object
    dklen: int
    n, p, r: int
    salt: string

  KdfPbkdf2* = object
    dklen: int
    c: int
    prf: string
    salt: string

  KdfParams = KdfPbkdf2 | KdfScrypt

  Kdf[T: KdfParams] = object
    function: string
    params: T
    message: string

  Crypto[T: KdfParams] = object
    kdf: Kdf[T]
    checksum: Checksum
    cipher: Cipher

  Keystore[T: KdfParams] = object
    crypto: Crypto[T]
    pubkey: string
    path: string
    uuid: string
    version: int

  KsResult*[T] = Result[T, cstring]

const
  saltSize = 32

  scryptParams = KdfScrypt(
    dklen: saltSize,
    n: 2^18,
    r: 1,
    p: 8
  )

  pbkdf2Params = KdfPbkdf2(
    dklen: saltSize,
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

template tryJsonToCrypto(ks: JsonNode; crypto: typedesc): untyped =
  try:
    ks{"crypto"}.to(Crypto[crypto])
  except Exception:
    return err "ks: failed to parse crypto"

template hexToBytes(data, name: string): untyped =
  try:
    hexToSeqByte(data)
  except ValueError:
    return err "ks: failed to parse " & name

proc decryptKeystore*(data, passphrase: string): KsResult[seq[byte]] =
  let ks =
    try:
      parseJson(data)
    except Exception:
      return err "ks: failed to parse keystore"

  var
    decKey: seq[byte]
    salt: seq[byte]
    iv: seq[byte]
    cipherMsg: seq[byte]
    checksumMsg: seq[byte]

  let kdf = ks{"crypto", "kdf", "function"}.getStr

  case kdf
  of "scrypt":
    let crypto = tryJsonToCrypto(ks, KdfScrypt)
    return err "ks: scrypt not supported"
  of "pbkdf2":
    let
      crypto = tryJsonToCrypto(ks, KdfPbkdf2)
      kdfParams = crypto.kdf.params

    salt = hexToBytes(kdfParams.salt, "salt")
    decKey = sha256.pbkdf2(passphrase, salt, kdfParams.c, kdfParams.dklen)
    iv = hexToBytes(crypto.cipher.params.iv, "iv")
    cipherMsg = hexToBytes(crypto.cipher.message, "cipher")
    checksumMsg = hexToBytes(crypto.checksum.message, "checksum")
  else:
    return err "ks: unknown cipher"

  if decKey.len < saltSize:
    return err "ks: decryption key must be at least 32 bytes"

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

proc encryptKeystore*[T: KdfParams](secret: openarray[byte];
                                    passphrase: string;
                                    path="";
                                    salt: openarray[byte] = @[];
                                    iv: openarray[byte] = @[];
                                    ugly=true): KsResult[string] =
  var
    decKey: seq[byte]
    aesCipher: CTR[aes128]
    aesIv = newSeq[byte](aes128.sizeBlock)
    kdfSalt = newSeq[byte](saltSize)
    cipherMsg = newSeq[byte](secret.len)

  if salt.len == saltSize:
    kdfSalt = @salt
  elif salt.len > 0:
    return err "ks: invalid salt"
  elif randomBytes(kdfSalt) != saltSize:
    return err "ks: no random bytes for salt"

  if iv.len == aes128.sizeBlock:
    aesIv = @iv
  elif iv.len > 0:
    return err "ks: invalid iv"
  elif randomBytes(aesIv) != aes128.sizeBlock:
    return err "ks: no random bytes for iv"

  when T is KdfPbkdf2:
    decKey = sha256.pbkdf2(passphrase, kdfSalt, pbkdf2Params.c,
                           pbkdf2Params.dklen)

    var kdf = Kdf[KdfPbkdf2](function: "pbkdf2", params: pbkdf2Params, message: "")
    kdf.params.salt = kdfSalt.toHex()
  else:
    return

  aesCipher.init(decKey.toOpenArray(0, 15), aesIv)
  aesCipher.encrypt(secret, cipherMsg)
  aesCipher.clear()

  let pubkey = (? ValidatorPrivkey.fromRaw(secret)).toPubKey()

  let
    sum = shaChecksum(decKey.toOpenArray(16, 31), cipherMsg)

    keystore = Keystore[T](
      crypto: Crypto[T](
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
      pubkey: pubkey.toHex(),
      path: path,
      uuid: $(? uuidGenerate()),
      version: 4
    )

  result = ok(if ugly: $(%keystore)
              else: pretty(%keystore, indent=4))
