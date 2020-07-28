# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  json, math, strutils, strformat, typetraits, bearssl,
  stew/[results, byteutils, bitseqs, bitops2], stew/shims/macros,
  eth/keyfile/uuid, blscurve, json_serialization,
  nimcrypto/[sha2, rijndael, pbkdf2, bcmode, hash, utils],
  ./datatypes, ./crypto, ./digest, ./signatures

export
  results, burnMem

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

  # https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md#specification
  Wallet* = object
    uuid*: UUID
    name*: WalletName
    version*: uint
    walletType* {.serializedFieldName: "type"}: string
    # TODO: The use of `JsonString` can be removed once we
    #       solve the serialization problem for `Crypto[T]`
    crypto*: JsonString
    nextAccount* {.serializedFieldName: "nextaccount".}: Natural

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

  UUID* = distinct string
  WalletName* = distinct string
  Mnemonic* = distinct string
  KeyPath* = distinct string
  KeyStorePass* = distinct string
  KeySeed* = distinct seq[byte]

  KeyStoreContent* = distinct JsonString
  WalletContent* = distinct JsonString

  SensitiveData = Mnemonic|KeyStorePass|KeySeed

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

UUID.serializesAsBaseIn Json
WalletName.serializesAsBaseIn Json

template `$`*(m: Mnemonic): string =
  string(m)

template `==`*(lhs, rhs: WalletName): bool =
  string(lhs) == string(rhs)

template `$`*(x: WalletName): string =
  string(x)

template burnMem*(m: var (SensitiveData|TaintedString)) =
  # TODO: `burnMem` in nimcrypto could use distinctBase
  #       to make its usage less error-prone.
  utils.burnMem(string m)

proc getRandomBytes*(rng: var BrHmacDrbgContext, n: Natural): seq[byte]
                    {.raises: [Defect].} =
  result = newSeq[byte](n)
  brHmacDrbgGenerate(rng, result)

macro wordListArray*(filename: static string,
                     maxWords: static int = 0,
                     minWordLength: static int = 0): untyped =
  result = newTree(nnkBracket)
  var words = slurp(filename).split()
  for word in words:
    if word.len >= minWordLength:
      result.add newCall("cstring", newLit(word))
      if maxWords > 0 and result.len >= maxWords:
        return

const
  englishWords = wordListArray("english_word_list.txt",
                                maxWords = wordListLen)

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

proc generateMnemonic*(
    rng: var BrHmacDrbgContext,
    words: openarray[cstring] = englishWords,
    entropyParam: openarray[byte] = @[]): Mnemonic =
  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
  doAssert words.len == wordListLen

  var entropy: seq[byte]
  if entropyParam.len == 0:
    setLen(entropy, 32)
    brHmacDrbgGenerate(rng, entropy)
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

template tryJsonToCrypto(json: JsonNode; crypto: typedesc): untyped =
  try:
    json.to(Crypto[crypto])
  except Exception:
    return err "ks: failed to parse crypto"

template hexToBytes(data, name: string): untyped =
  try:
    hexToSeqByte(data)
  except ValueError:
    return err "ks: failed to parse " & name

proc decryptoCryptoField*(json: JsonNode,
                          password:  KeyStorePass): KsResult[seq[byte]] =
  var
    decKey: seq[byte]
    salt: seq[byte]
    iv: seq[byte]
    cipherMsg: seq[byte]
    checksumMsg: seq[byte]

  let kdf = json{"kdf", "function"}.getStr

  case kdf
  of "scrypt":
    let crypto = tryJsonToCrypto(json, KdfScrypt)
    return err "ks: scrypt not supported"
  of "pbkdf2":
    let
      crypto = tryJsonToCrypto(json, KdfPbkdf2)
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

  ok secret

proc decryptKeystore*(data: KeyStoreContent,
                      password: KeyStorePass): KsResult[ValidatorPrivKey] =
  # TODO: `parseJson` can raise a general `Exception`
  let
    ks = try: parseJson(data.string)
         except Exception: return err "ks: failed to parse keystore"
    secret = decryptoCryptoField(ks{"crypto"}, password)

  ValidatorPrivKey.fromRaw(? secret)

proc createCryptoField(T: type[KdfParams],
                       rng: var BrHmacDrbgContext,
                       secret: openarray[byte],
                       password = KeyStorePass "",
                       salt: openarray[byte] = @[],
                       iv: openarray[byte] = @[]): Crypto[T] =
  type AES = aes128

  var
    decKey: seq[byte]
    aesCipher: CTR[AES]
    cipherMsg = newSeq[byte](secret.len)

  let kdfSalt = if salt.len > 0:
    doAssert salt.len == saltSize
    @salt
  else:
    getRandomBytes(rng, saltSize)

  let aesIv = if iv.len > 0:
    doAssert iv.len == AES.sizeBlock
    @iv
  else:
    getRandomBytes(rng, AES.sizeBlock)

  when T is KdfPbkdf2:
    decKey = sha256.pbkdf2(password.string, kdfSalt, pbkdf2Params.c,
                           pbkdf2Params.dklen)

    var kdf = Kdf[KdfPbkdf2](function: "pbkdf2", params: pbkdf2Params, message: "")
    kdf.params.salt = byteutils.toHex(kdfSalt)
  else:
    {.fatal: "Other KDFs are supported yet".}

  aesCipher.init(decKey.toOpenArray(0, 15), aesIv)
  aesCipher.encrypt(secret, cipherMsg)
  aesCipher.clear()

  let sum = shaChecksum(decKey.toOpenArray(16, 31), cipherMsg)

  Crypto[T](
    kdf: kdf,
    checksum: Checksum(
      function: "sha256",
      message: byteutils.toHex(sum)),
    cipher: Cipher(
      function: "aes-128-ctr",
      params: CipherParams(iv: byteutils.toHex(aesIv)),
      message: byteutils.toHex(cipherMsg)))

proc encryptKeystore*(T: type[KdfParams],
                      rng: var BrHmacDrbgContext,
                      privKey: ValidatorPrivkey,
                      password = KeyStorePass "",
                      path = KeyPath "",
                      salt: openarray[byte] = @[],
                      iv: openarray[byte] = @[],
                      pretty = true): KeyStoreContent =
  let
    secret = privKey.toRaw[^32..^1]
    cryptoField = createCryptoField(T, rng, secret, password, salt, iv)
    pubkey = privKey.toPubKey()
    uuid = uuidGenerate().expect("Random bytes should be available")
    keystore = Keystore[T](
      crypto: cryptoField,
      pubkey: toHex(pubkey),
      path: path.string,
      uuid: $uuid,
      version: 4)

  KeyStoreContent if pretty: json.pretty(%keystore)
                  else: $(%keystore)

proc createWallet*(T: type[KdfParams],
                   rng: var BrHmacDrbgContext,
                   mnemonic: Mnemonic,
                   name = WalletName "",
                   salt: openarray[byte] = @[],
                   iv: openarray[byte] = @[],
                   password = KeyStorePass "",
                   nextAccount = none(Natural),
                   pretty = true): Wallet =
  let
    uuid = UUID $(uuidGenerate().expect("Random bytes should be available"))
    # Please note that we are passing an empty password here because
    # we want the wallet restoration procedure to depend only on the
    # mnemonic (the user is asked to treat the mnemonic as a password).
    seed = getSeed(mnemonic, KeyStorePass"")
    cryptoField = %createCryptoField(T,rng, distinctBase seed, password, salt, iv)

  Wallet(
    uuid: uuid,
    name: if name.string.len > 0: name
          else: WalletName(uuid),
    version: 1,
    walletType: "hierarchical deterministic",
    crypto: JsonString(if pretty: json.pretty(cryptoField)
                       else: $cryptoField),
    nextAccount: nextAccount.get(0))

proc createWalletContent*(T: type[KdfParams],
                          rng: var BrHmacDrbgContext,
                          mnemonic: Mnemonic,
                          name = WalletName "",
                          salt: openarray[byte] = @[],
                          iv: openarray[byte] = @[],
                          password = KeyStorePass "",
                          nextAccount = none(Natural),
                          pretty = true): (UUID, WalletContent) =
  let wallet = createWallet(
    T, rng, mnemonic, name, salt, iv, password, nextAccount, pretty)
  (wallet.uuid, WalletContent Json.encode(wallet, pretty = pretty))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/deposit-contract.md#withdrawal-credentials
proc makeWithdrawalCredentials*(k: ValidatorPubKey): Eth2Digest =
  var bytes = eth2digest(k.toRaw())
  bytes.data[0] = BLS_WITHDRAWAL_PREFIX.uint8
  bytes

proc prepareDeposit*(preset: RuntimePreset,
                     withdrawalPubKey: ValidatorPubKey,
                     signingKey: ValidatorPrivKey, signingPubKey: ValidatorPubKey,
                     amount = MAX_EFFECTIVE_BALANCE.Gwei): DepositData =
  var res = DepositData(
    amount: amount,
    pubkey: signingPubKey,
    withdrawal_credentials: makeWithdrawalCredentials(withdrawalPubKey))

  res.signature = preset.get_deposit_signature(res, signingKey)
  return res

