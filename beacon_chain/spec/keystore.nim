# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  math, strutils, strformat, typetraits, algorithm,
  stew/[results, byteutils, bitseqs, bitops2], stew/shims/macros,
  bearssl, eth/keyfile/uuid, blscurve, faststreams/textio, json_serialization,
  nimcrypto/[sha2, rijndael, pbkdf2, bcmode, hash, utils, scrypt],
  ./datatypes, ./crypto, ./digest, ./signatures

export
  results, burnMem, writeValue, readValue

{.push raises: [Defect].}

type
  ChecksumFunctionKind* = enum
    sha256Checksum = "sha256"

  Sha256Params* = object
  Sha256Digest* = MDigest[256]

  ChecksumBytes* = distinct seq[byte]

  Checksum* = object
    case function*: ChecksumFunctionKind
    of sha256Checksum:
      params*: Sha256Params
      message*: Sha256Digest

  Aes128CtrIv* = distinct seq[byte]

  Aes128CtrParams* = object
    iv*: Aes128CtrIv

  CipherFunctionKind* = enum
    aes128CtrCipher = "aes-128-ctr"

  CipherBytes* = distinct seq[byte]

  Cipher* = object
    case function*: CipherFunctionKind
    of aes128ctrCipher:
      params*: Aes128CtrParams
    message*: CipherBytes

  KdfKind* = enum
    kdfPbkdf2 = "pbkdf2"
    kdfScrypt = "scrypt"

  ScryptSalt* = distinct seq[byte]

  ScryptParams* = object
    dklen: int
    n, p, r: int
    salt: ScryptSalt

  Pbkdf2Salt* = distinct seq[byte]

  PrfKind* = enum # Pseudo-random-function Kind
    HmacSha256 = "hmac-sha256"

  Pbkdf2Params* = object
    dklen*: int
    c*: int
    prf*: PrfKind
    salt*: Pbkdf2Salt

  # https://github.com/ethereum/EIPs/blob/4494da0966afa7318ec0157948821b19c4248805/EIPS/eip-2386.md#specification
  Wallet* = object
    uuid*: UUID
    name*: WalletName
    version*: uint
    walletType* {.serializedFieldName: "type"}: string
    # TODO: The use of `JsonString` can be removed once we
    #       solve the serialization problem for `Crypto[T]`
    crypto*: Crypto
    nextAccount* {.serializedFieldName: "nextaccount".}: Natural

  Kdf* = object
    case function*: KdfKind
    of kdfPbkdf2:
      pbkdf2Params* {.serializedFieldName: "params".}: Pbkdf2Params
    of kdfScrypt:
      scryptParams* {.serializedFieldName: "params".}: ScryptParams
    message*: string

  Crypto* = object
    kdf*: Kdf
    checksum*: Checksum
    cipher*: Cipher

  Keystore* = object
    crypto*: Crypto
    description*: ref string
    pubkey*: ValidatorPubKey
    path*: KeyPath
    uuid*: string
    version*: int

  KsResult*[T] = Result[T, string]

  Eth2KeyKind* = enum
    signingKeyKind # Also known as voting key
    withdrawalKeyKind

  UUID* = distinct string
  WalletName* = distinct string
  Mnemonic* = distinct string
  KeyPath* = distinct string
  KeystorePass* = distinct string
  KeySeed* = distinct seq[byte]

  Credentials* = object
    mnemonic*: Mnemonic
    keystore*: Keystore
    signingKey*: ValidatorPrivKey
    withdrawalKey*: ValidatorPrivKey

  SensitiveData = Mnemonic|KeystorePass|KeySeed
  SimpleHexEncodedTypes = ScryptSalt|ChecksumBytes|CipherBytes

const
  keyLen = 32

  scryptParams = ScryptParams(
    dklen: keyLen,
    n: 2^18,
    p: 1,
    r: 8
  )

  pbkdf2Params = Pbkdf2Params(
    dklen: keyLen,
    c: 2^18,
    prf: HmacSha256
  )

  # https://eips.ethereum.org/EIPS/eip-2334
  eth2KeyPurpose = 12381
  eth2CoinType* = 3600

  # https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
  wordListLen = 2048
  maxWordLen = 16

UUID.serializesAsBaseIn Json
KeyPath.serializesAsBaseIn Json
WalletName.serializesAsBaseIn Json

ChecksumFunctionKind.serializesAsTextInJson
CipherFunctionKind.serializesAsTextInJson
PrfKind.serializesAsTextInJson
KdfKind.serializesAsTextInJson

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

func longName*(wallet: Wallet): string =
  if wallet.name.string == wallet.uuid.string:
    wallet.name.string
  else:
    wallet.name.string & " (" & wallet.uuid.string & ")"

proc getRandomBytes*(rng: var BrHmacDrbgContext, n: Natural): seq[byte]
                    {.raises: [Defect].} =
  result = newSeq[byte](n)
  brHmacDrbgGenerate(rng, result)

macro wordListArray*(filename: static string,
                     maxWords: static int = 0,
                     minWordLen: static int = 0,
                     maxWordLen: static int = high(int)): untyped =
  result = newTree(nnkBracket)
  var words = slurp(filename).split()
  for word in words:
    if word.len >= minWordLen and word.len <= maxWordLen:
      result.add newCall("cstring", newLit(word))
      if maxWords > 0 and result.len >= maxWords:
        return

const
  englishWords = wordListArray("english_word_list.txt",
                                maxWords = wordListLen,
                                maxWordLen = maxWordLen)

static:
  doAssert englishWords.len == wordListLen

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

func getSeed*(mnemonic: Mnemonic, password: KeystorePass): KeySeed =
  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
  let salt = "mnemonic-" & password.string
  KeySeed sha512.pbkdf2(mnemonic.string, salt, 2048, 64)

template add(m: var Mnemonic, s: cstring) =
  m.string.add s

proc generateMnemonic*(
    rng: var BrHmacDrbgContext,
    words: openarray[cstring] = englishWords,
    entropyParam: openarray[byte] = @[]): Mnemonic =
  ## Generates a valid BIP-0039 mnenomic:
  ## https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
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

  # Make sure the string won't be reallocated as this may
  # leave partial copies of the mnemonic in memory:
  result = Mnemonic newStringOfCap(mnemonicWordCount * maxWordLen)
  result.add words[entropy.getBitsBE(0..10)]

  for i in 1 ..< mnemonicWordCount:
    let
      firstBit = i*11
      lastBit = firstBit + 10
    result.add " "
    result.add words[entropy.getBitsBE(firstBit..lastBit)]

proc cmpIgnoreCase(lhs: cstring, rhs: string): int =
  # TODO: This is a bit silly.
  # Nim should have a `cmp` function for C strings.
  cmpIgnoreCase($lhs, rhs)

proc validateMnemonic*(inputWords: TaintedString,
                       outputMnemonic: var Mnemonic): bool =
  ## Accept a case-insensitive input string and returns `true`
  ## if it represents a valid mnenomic. The `outputMnemonic`
  ## value will be populated with a normalized lower-case
  ## version of the mnemonic using a single space separator.
  ##
  ## The `outputMnemonic` value may be populated partially
  ## with sensitive data even in case of validator failure.
  ## Make sure to burn the received data after usage.

  let words = inputWords.string.strip.split(Whitespace)
  if words.len < 12 or words.len > 24 or words.len mod 3 != 0:
    return false

  # Make sure the string won't be re-allocated as this may
  # leave partial copies of the mnemonic in memory:
  outputMnemonic = Mnemonic newStringOfCap(words.len * maxWordLen)

  for word in words:
    let foundIdx = binarySearch(englishWords, word, cmpIgnoreCase)
    if foundIdx == -1:
      return false
    if outputMnemonic.string.len > 0:
      outputMnemonic.add " "
    outputMnemonic.add englishWords[foundIdx]

  return true

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
                      password: KeystorePass): ValidatorPrivKey =
  deriveMasterKey(getSeed(mnemonic, password))

proc deriveChildKey*(masterKey: ValidatorPrivKey,
                     path: KeyPath): ValidatorPrivKey =
  result = masterKey
  for idx in pathNodes(path):
    result = deriveChildKey(result, idx)

proc keyFromPath*(mnemonic: Mnemonic,
                  password: KeystorePass,
                  path: KeyPath): ValidatorPrivKey =
  deriveChildKey(deriveMasterKey(mnemonic, password), path)

proc shaChecksum(key, cipher: openarray[byte]): Sha256Digest =
  var ctx: sha256
  ctx.init()
  ctx.update(key)
  ctx.update(cipher)
  result = ctx.finish()
  ctx.clear()

proc writeJsonHexString(s: OutputStream, data: openarray[byte])
                       {.raises: [IOError, Defect].} =
  s.write '"'
  s.writeHex data
  s.write '"'

proc readValue*(r: var JsonReader, value: var Pbkdf2Salt)
               {.raises: [SerializationError, IOError, Defect].} =
  var s = r.readValue(string)

  if s.len == 0 or s.len mod 16 != 0:
    r.raiseUnexpectedValue(
      "The Pbkdf2Salt salf must have a non-zero length divisible by 16")

  try:
    value = Pbkdf2Salt hexToSeqByte(s)
  except ValueError:
    r.raiseUnexpectedValue(
      "The Pbkdf2Salt must be a valid hex string")

proc readValue*(r: var JsonReader, value: var Aes128CtrIv)
               {.raises: [SerializationError, IOError, Defect].} =
  var s = r.readValue(string)

  if s.len != 32:
    r.raiseUnexpectedValue(
      "The aes-128-ctr IV must be a string of length 32")

  try:
    value = Aes128CtrIv hexToSeqByte(s)
  except ValueError:
    r.raiseUnexpectedValue(
      "The aes-128-ctr IV must be a valid hex string")

proc readValue*[T: SimpleHexEncodedTypes](r: var JsonReader, value: var T)
               {.raises: [SerializationError, IOError, Defect].} =
  try:
    value = T hexToSeqByte(r.readValue(string))
  except ValueError:
    r.raiseUnexpectedValue("Valid hex string expected")

proc readValue*(r: var JsonReader, value: var Kdf)
               {.raises: [SerializationError, IOError, Defect].} =
  var
    functionSpecified = false
    paramsSpecified = false

  for fieldName in readObjectFields(r):
    case fieldName
    of "function":
      value.function = r.readValue(KdfKind)
      functionSpecified = true

    of "params":
      if functionSpecified:
        case value.function
        of kdfPbkdf2:
          r.readValue(value.pbkdf2Params)
        of kdfScrypt:
          r.readValue(value.scryptParams)
      else:
        r.raiseUnexpectedValue(
          "The 'params' field must be specified after the 'function' field")
      paramsSpecified = true

    of "message":
      r.readValue(value.message)

    else:
      r.raiseUnexpectedField(fieldName, "Kdf")

  if not (functionSpecified and paramsSpecified):
    r.raiseUnexpectedValue(
      "The Kdf value should have sub-fields named 'function' and 'params'")

template writeValue*(w: var JsonWriter,
                     value: Pbkdf2Salt|SimpleHexEncodedTypes|Aes128CtrIv) =
  writeJsonHexString(w.stream, distinctBase value)

template bytes(value: Pbkdf2Salt|SimpleHexEncodedTypes|Aes128CtrIv): seq[byte] =
  distinctBase value

func scrypt(password: openArray[char], salt: openArray[byte],
            N, r, p, keyLen: static[int]): array[keyLen, byte] =
  let (xyvLen, bLen) = scryptCalc(N, r, p)
  var xyv = newSeq[uint32](xyvLen)
  var b = newSeq[byte](bLen)
  discard scrypt(password, salt, N, r, p, xyv, b, result)

proc decryptCryptoField*(crypto: Crypto, password: KeystorePass): seq[byte] =
  ## Returns 0 bytes if the supplied password is incorrect

  let decKey = case crypto.kdf.function
    of kdfPbkdf2:
      template params: auto = crypto.kdf.pbkdf2Params
      sha256.pbkdf2(password.string, params.salt.bytes, params.c, params.dklen)
    of kdfScrypt:
      template params: auto = crypto.kdf.scryptParams
      if params.dklen != scryptParams.dklen or
         params.n != scryptParams.n or
         params.r != scryptParams.r or
         params.p != scryptParams.p:
        # TODO This should be reported in a better way
        return
      @(scrypt(password.string,
               params.salt.bytes,
               scryptParams.n,
               scryptParams.r,
               scryptParams.p,
               scryptParams.dklen))

  let derivedChecksum = shaChecksum(decKey.toOpenArray(16, 31),
                                    crypto.cipher.message.bytes)
  if derivedChecksum != crypto.checksum.message:
    return

  var
    aesCipher: CTR[aes128]
    secret = newSeq[byte](crypto.cipher.message.bytes.len)

  aesCipher.init(decKey.toOpenArray(0, 15), crypto.cipher.params.iv.bytes)
  aesCipher.decrypt(crypto.cipher.message.bytes, secret)
  aesCipher.clear()

  return secret

func cstringToStr(v: cstring): string = $v

proc decryptKeystore*(keystore: Keystore,
                      password: KeystorePass): KsResult[ValidatorPrivKey] =
  let decryptedBytes = decryptCryptoField(keystore.crypto, password)
  if decryptedBytes.len > 0:
    return ValidatorPrivKey.fromRaw(decryptedBytes).mapErr(cstringToStr)

proc decryptKeystore*(keystore: JsonString,
                      password: KeystorePass): KsResult[ValidatorPrivKey] =
  let keystore = try: Json.decode(keystore.string, Keystore)
                 except SerializationError as e:
                   return err e.formatMsg("<keystore>")
  decryptKeystore(keystore, password)

proc createCryptoField(kdfKind: KdfKind,
                       rng: var BrHmacDrbgContext,
                       secret: openarray[byte],
                       password = KeystorePass "",
                       salt: openarray[byte] = @[],
                       iv: openarray[byte] = @[]): Crypto =
  type AES = aes128

  let kdfSalt =
    if salt.len > 0:
      doAssert salt.len == keyLen
      @salt
    else:
      getRandomBytes(rng, keyLen)

  let aesIv = if iv.len > 0:
    doAssert iv.len == AES.sizeBlock
    @iv
  else:
    getRandomBytes(rng, AES.sizeBlock)

  var decKey: seq[byte]
  let kdf = case kdfKind
    of kdfPbkdf2:
      decKey = sha256.pbkdf2(password.string,
                             kdfSalt,
                             pbkdf2Params.c,
                             pbkdf2Params.dklen)
      var params = pbkdf2Params
      params.salt = Pbkdf2Salt kdfSalt
      Kdf(function: kdfPbkdf2, pbkdf2Params: params, message: "")
    of kdfScrypt:
      decKey = @(scrypt(password.string, kdfSalt,
                        scryptParams.n, scryptParams.r, scryptParams.p, keyLen))
      var params = scryptParams
      params.salt = ScryptSalt kdfSalt
      Kdf(function: kdfScrypt, scryptParams: params, message: "")

  var
    aesCipher: CTR[AES]
    cipherMsg = newSeq[byte](secret.len)

  aesCipher.init(decKey.toOpenArray(0, 15), aesIv)
  aesCipher.encrypt(secret, cipherMsg)
  aesCipher.clear()

  let sum = shaChecksum(decKey.toOpenArray(16, 31), cipherMsg)

  Crypto(
    kdf: kdf,
    checksum: Checksum(
      function: sha256Checksum,
      message: sum),
    cipher: Cipher(
      function: aes128CtrCipher,
      params: Aes128CtrParams(iv: Aes128CtrIv aesIv),
      message: CipherBytes cipherMsg))

proc createKeystore*(kdfKind: KdfKind,
                     rng: var BrHmacDrbgContext,
                     privKey: ValidatorPrivkey,
                     password = KeystorePass "",
                     path = KeyPath "",
                     description = "",
                     salt: openarray[byte] = @[],
                     iv: openarray[byte] = @[]): Keystore =
  let
    secret = privKey.toRaw[^32..^1]
    cryptoField = createCryptoField(kdfKind, rng, secret, password, salt, iv)
    pubkey = privKey.toPubKey()
    uuid = uuidGenerate().expect("Random bytes should be available")

  Keystore(
    crypto: cryptoField,
    pubkey: pubkey,
    path: path,
    description: newClone(description),
    uuid: $uuid,
    version: 4)

proc createWallet*(kdfKind: KdfKind,
                   rng: var BrHmacDrbgContext,
                   mnemonic: Mnemonic,
                   name = WalletName "",
                   salt: openarray[byte] = @[],
                   iv: openarray[byte] = @[],
                   password = KeystorePass "",
                   nextAccount = none(Natural),
                   pretty = true): Wallet =
  let
    uuid = UUID $(uuidGenerate().expect("Random bytes should be available"))
    # Please note that we are passing an empty password here because
    # we want the wallet restoration procedure to depend only on the
    # mnemonic (the user is asked to treat the mnemonic as a password).
    seed = getSeed(mnemonic, KeystorePass"")
    crypto = createCryptoField(kdfKind, rng, distinctBase seed,
                               password, salt, iv)
  Wallet(
    uuid: uuid,
    name: if name.string.len > 0: name
          else: WalletName(uuid),
    version: 1,
    walletType: "hierarchical deterministic",
    crypto: crypto,
    nextAccount: nextAccount.get(0))

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

