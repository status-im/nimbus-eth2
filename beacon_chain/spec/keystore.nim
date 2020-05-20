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
  scryptParams = KdfScrypt(
    dklen: 32,
    n: 2^18,
    r: 1,
    p: 8
  )

  pbkdf2Params = KdfPbkdf2(
    dklen: 32,
    c: 2^18,
    prf: "hmac-sha256"
  )

template shaChecksum(key, cipher: openarray[byte]): untyped =
  var ctx: sha256
  ctx.init()
  ctx.update(key)
  ctx.update(cipher)
  ctx.finish().data

proc decryptKeystore*(data, passphrase: string): KsResult[seq[byte]] =
  var ks: JsonNode
  try:
    ks = parseJson(data)
  except JsonParsingError:
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
    let crypto = ks{"crypto"}.to(Crypto[KdfScrypt])
    return err "ks: scrypt not supported"
  of "pbkdf2":
    let
      crypto = ks{"crypto"}.to(Crypto[KdfPbkdf2])
      kdfParams = crypto.kdf.params

    salt = hexToSeqByte(kdfParams.salt)
    decKey = sha256.pbkdf2(passphrase, salt, kdfParams.c, kdfParams.dklen)
    iv = hexToSeqByte(crypto.cipher.params.iv)
    cipherMsg = hexToSeqByte(crypto.cipher.message)
    checksumMsg = hexToSeqByte(crypto.checksum.message)
  else:
    return err "ks: unknown cipher"

  if decKey.len < 32:
    return err "ks: decryption key must be at least 32 bytes"

  let sum = shaChecksum(decKey[16..<32], cipherMsg)
  if sum != checksumMsg:
    return err "ks: invalid checksum"

  var
    aesCipher: CTR[aes128]
    secret = newSeq[byte](cipherMsg.len)

  aesCipher.init(decKey[0..<16], iv)
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
    aesIv = newSeq[byte](16)
    kdfSalt = newSeq[byte](32)
    cipherMsg = newSeq[byte](secret.len)

  if salt.len == 32:
    kdfSalt = @salt
  elif salt.len > 0:
    return err "ks: invalid salt"
  elif randomBytes(kdfSalt) != 32:
    return err "ks: no random bytes for salt"

  if iv.len == 16:
    aesIv = @iv
  elif iv.len > 0:
    return err "ks: invalid iv"
  elif randomBytes(aesIv) != 16:
    return err "ks: no random bytes for iv"

  when T is KdfPbkdf2:
    decKey = sha256.pbkdf2(passphrase, kdfSalt, pbkdf2Params.c,
                           pbkdf2Params.dklen)

    var kdf = Kdf[KdfPbkdf2](function: "pbkdf2", params: pbkdf2Params, message: "")
    kdf.params.salt = kdfSalt.toHex()
  else:
    return

  aesCipher.init(decKey[0..<16], aesIv)
  aesCipher.encrypt(secret, cipherMsg)
  aesCipher.clear()

  let
    privkey = ValidatorPrivkey.fromRaw(secret)
    pubkey = privkey.tryGet().toPubKey()

    sum = shaChecksum(decKey[16..<32], cipherMsg)

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
      uuid: $(uuidGenerate().tryGet()), # error handling?
      version: 4
    )

  result = ok(if ugly: $(%keystore)
              else: pretty(%keystore, indent=4))
