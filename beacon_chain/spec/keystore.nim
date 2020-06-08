# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  json, math, strutils, strformat,
  stew/[results, byteutils, bitseqs, bitops2], stew/shims/macros,
  eth/keyfile/uuid, blscurve,
  nimcrypto/[sha2, rijndael, pbkdf2, bcmode, hash, sysrand],
  datatypes, crypto, digest, helpers

export
  results

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

  Eth2KeyKind* = enum
    signingKeyKind # Also known as voting key
    withdrawalKeyKind

  Mnemonic* = distinct string
  KeyPath* = distinct string
  KeyStorePass* = distinct string
  KeyStoreContent* = distinct JsonString
  KeySeed* = distinct seq[byte]

  Credentials* = object
    mnemonic*: Mnemonic
    keyStore*: KeyStoreContent
    signingKey*: ValidatorPrivKey
    withdrawalKey*: ValidatorPrivKey

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

  # https://eips.ethereum.org/EIPS/eip-2334
  eth2KeyPurpose = 12381
  eth2CoinType* = 3600

  # https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
  wordListLen = 2048

macro wordListArray(filename: static string): array[wordListLen, cstring] =
  result = newTree(nnkBracket)
  var words = slurp(filename).split()
  words.setLen wordListLen
  for word in words:
    result.add newCall("cstring", newLit(word))

const
  englishWords = wordListArray "english_word_list.txt"

iterator pathNodesImpl(path: string): Natural
                      {.raises: [ValueError].} =
  for elem in path.split("/"):
    if elem == "m": continue
    yield parseInt(elem)

func append*(path: KeyPath, pathNode: Natural): KeyPath =
  KeyPath(path.string & "/" & $pathNode)

func validateKeyPath*(path: TaintedString): KeyPath
                     {.raises: [ValueError].} =
  for elem in pathNodesImpl(path.string): discard elem
  KeyPath path

iterator pathNodes(path: KeyPath): Natural =
  try:
    for elem in pathNodesImpl(path.string):
      yield elem
  except ValueError:
    doAssert false, "Make sure you've validated the key path with `validateKeyPath`"

func makeKeyPath*(validatorIdx: Natural,
                  keyType: Eth2KeyKind): KeyPath =
  # https://eips.ethereum.org/EIPS/eip-2334
  let use = case keyType
            of withdrawalKeyKind: "0"
            of signingKeyKind: "0/0"

  try:
    KeyPath &"m/{eth2KeyPurpose}/{eth2CoinType}/{validatorIdx}/{use}"
  except ValueError:
    raiseAssert "All values above can be converted successfully to strings"

func getSeed*(mnemonic: Mnemonic, password: KeyStorePass): KeySeed =
  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
  let salt = "mnemonic-" & password.string
  KeySeed sha512.pbkdf2(mnemonic.string, salt, 2048, 64)

proc generateMnemonic*(words: openarray[cstring],
                       entropyParam: openarray[byte] = @[]): Mnemonic =
  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
  doAssert words.len == wordListLen

  var entropy: seq[byte]
  if entropyParam.len == 0:
    entropy = getRandomBytesOrPanic(32)
  else:
    doAssert entropyParam.len >= 128 and
             entropyParam.len <= 256 and
             entropyParam.len mod 32 == 0
    entropy = @entropyParam

  let
    checksumBits = entropy.len div 4 # ranges from 4 to 8
    mnemonicWordCount = 12 + (checksumBits - 4) * 3
    checksum = sha256.digest(entropy)

  entropy.add byte(checksum.data.getBitsBE(0 ..< checksumBits))

  var res = ""
  res.add words[entropy.getBitsBE(0..10)]

  for i in 1 ..< mnemonicWordCount:
    let
      firstBit = i*11
      lastBit = firstBit + 10
    res.add " "
    res.add words[entropy.getBitsBE(firstBit..lastBit)]

  Mnemonic res

proc deriveChildKey*(parentKey: ValidatorPrivKey,
                     index: Natural): ValidatorPrivKey =
  let success = derive_child_secretKey(SecretKey result,
                                       SecretKey parentKey,
                                       uint32 index)
  # TODO `derive_child_secretKey` is reporting pre-condition
  #       failures with return values. We should turn the checks
  #       into asserts inside the function.
  doAssert success

proc deriveMasterKey*(seed: KeySeed): ValidatorPrivKey =
  let success = derive_master_secretKey(SecretKey result,
                                        seq[byte] seed)
  # TODO `derive_master_secretKey` is reporting pre-condition
  #       failures with return values. We should turn the checks
  #       into asserts inside the function.
  doAssert success

proc deriveMasterKey*(mnemonic: Mnemonic,
                      password: KeyStorePass): ValidatorPrivKey =
  deriveMasterKey(getSeed(mnemonic, password))

proc deriveChildKey*(masterKey: ValidatorPrivKey,
                     path: KeyPath): ValidatorPrivKey =
  result = masterKey
  for idx in pathNodes(path):
    result = deriveChildKey(result, idx)

proc keyFromPath*(mnemonic: Mnemonic,
                  password: KeyStorePass,
                  path: KeyPath): ValidatorPrivKey =
  deriveChildKey(deriveMasterKey(mnemonic, password), path)

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

proc decryptKeystore*(data: KeyStoreContent,
                      password: KeyStorePass): KsResult[ValidatorPrivKey] =
  # TODO: `parseJson` can raise a general `Exception`
  let ks = try: parseJson(data.string)
           except Exception: return err "ks: failed to parse keystore"

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
    decKey = sha256.pbkdf2(password.string, salt, kdfParams.c, kdfParams.dklen)
    iv = hexToBytes(crypto.cipher.params.iv, "iv")
    cipherMsg = hexToBytes(crypto.cipher.message, "cipher")
    checksumMsg = hexToBytes(crypto.checksum.message, "checksum")
  else:
    return err "ks: unknown cipher"

  if decKey.len < saltSize:
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

  ValidatorPrivKey.fromRaw(secret)

proc encryptKeystore*(T: type[KdfParams],
                      privKey: ValidatorPrivkey,
                      password = KeyStorePass "",
                      path = KeyPath "",
                      salt: openarray[byte] = @[],
                      iv: openarray[byte] = @[],
                      pretty = true): KeyStoreContent =
  var
    secret = privKey.toRaw[^32..^1]
    decKey: seq[byte]
    aesCipher: CTR[aes128]
    aesIv = newSeq[byte](aes128.sizeBlock)
    kdfSalt = newSeq[byte](saltSize)
    cipherMsg = newSeq[byte](secret.len)

  if salt.len > 0:
    doAssert salt.len == saltSize
    kdfSalt = @salt
  else:
    getRandomBytesOrPanic(kdfSalt)

  if iv.len > 0:
    doAssert iv.len == aes128.sizeBlock
    aesIv = @iv
  else:
    getRandomBytesOrPanic(aesIv)

  when T is KdfPbkdf2:
    decKey = sha256.pbkdf2(password.string, kdfSalt, pbkdf2Params.c,
                           pbkdf2Params.dklen)

    var kdf = Kdf[KdfPbkdf2](function: "pbkdf2", params: pbkdf2Params, message: "")
    kdf.params.salt = byteutils.toHex(kdfSalt)
  else:
    return

  aesCipher.init(decKey.toOpenArray(0, 15), aesIv)
  aesCipher.encrypt(secret, cipherMsg)
  aesCipher.clear()

  let pubkey = privKey.toPubKey()

  let
    sum = shaChecksum(decKey.toOpenArray(16, 31), cipherMsg)
    uuid = uuidGenerate().get

    keystore = Keystore[T](
      crypto: Crypto[T](
        kdf: kdf,
        checksum: Checksum(
          function: "sha256",
          message: byteutils.toHex(sum)
        ),
        cipher: Cipher(
          function: "aes-128-ctr",
          params: CipherParams(iv: byteutils.toHex(aesIv)),
          message: byteutils.toHex(cipherMsg)
        )
      ),
      pubkey: toHex(pubkey),
      path: path.string,
      uuid: $uuid,
      version: 4)

  KeyStoreContent if pretty: json.pretty(%keystore, indent=4)
                  else: $(%keystore)

proc restoreCredentials*(mnemonic: Mnemonic,
                         password = KeyStorePass ""): Credentials =
  let
    withdrawalKeyPath = makeKeyPath(0, withdrawalKeyKind)
    withdrawalKey = keyFromPath(mnemonic, password, withdrawalKeyPath)

    signingKeyPath = withdrawalKeyPath.append 0
    signingKey = deriveChildKey(withdrawalKey, 0)

  Credentials(
    mnemonic: mnemonic,
    keyStore: encryptKeystore(KdfPbkdf2, signingKey, password, signingKeyPath),
    signingKey: signingKey,
    withdrawalKey: withdrawalKey)

proc generateCredentials*(entropy: openarray[byte] = @[],
                          password = KeyStorePass ""): Credentials =
  let mnemonic = generateMnemonic(englishWords, entropy)
  restoreCredentials(mnemonic, password)

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/deposit-contract.md#withdrawal-credentials
proc makeWithdrawalCredentials*(k: ValidatorPubKey): Eth2Digest =
  var bytes = eth2hash(k.toRaw())
  bytes.data[0] = BLS_WITHDRAWAL_PREFIX.uint8
  bytes

proc prepareDeposit*(credentials: Credentials,
                     amount = MAX_EFFECTIVE_BALANCE.Gwei): Deposit =
  let
    withdrawalPubKey = credentials.withdrawalKey.toPubKey
    signingPubKey = credentials.signingKey.toPubKey

  var
    ret = Deposit(
      data: DepositData(
        amount: amount,
        pubkey: signingPubKey,
        withdrawal_credentials: makeWithdrawalCredentials(withdrawalPubKey)))

  let domain = compute_domain(DOMAIN_DEPOSIT)
  let signing_root = compute_signing_root(ret.getDepositMessage, domain)

  ret.data.signature = bls_sign(credentials.signingKey, signing_root.data)
  ret

