# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/[algorithm, math, parseutils, strformat, strutils, typetraits, unicode,
       uri, hashes],
  # Third-party libraries
  normalize,
  # Status libraries
  stew/[results, bitops2, base10, io2, endians2], stew/shims/macros,
  eth/keyfile/uuid, blscurve,
  json_serialization, json_serialization/std/options,
  chronos/timer,
  nimcrypto/[sha2, rijndael, pbkdf2, bcmode, hash, scrypt],
  # Local modules
  libp2p/crypto/crypto as lcrypto,
  ./datatypes/base,  ./signatures

export base, uri, io2, options

# We use `ncrutils` for constant-time hexadecimal encoding/decoding procedures.
import nimcrypto/utils as ncrutils

export
  results, burnMem, writeValue, readValue

{.localPassC: "-fno-lto".} # no LTO for crypto

type
  KeystoreMode* = enum
    Secure, Fast

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
    of aes128CtrCipher:
      params*: Aes128CtrParams
    message*: CipherBytes

  KdfKind* = enum
    kdfPbkdf2 = "pbkdf2"
    kdfScrypt = "scrypt"

  ScryptSalt* = distinct seq[byte]

  ScryptParams* = object
    dklen*: uint64
    n*, p*, r*: int
    salt*: ScryptSalt

  Pbkdf2Salt* = distinct seq[byte]

  PrfKind* = enum # Pseudo-random-function Kind
    HmacSha256 = "hmac-sha256"

  Pbkdf2Params* = object
    dklen*: uint64
    c*: uint64
    prf*: PrfKind
    salt*: Pbkdf2Salt

  DecryptionStatus* = enum
    Success = "Success"
    InvalidPassword = "Invalid password"
    InvalidKeystore = "Invalid keystore"

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
    description*: Option[string]
    pubkey*: ValidatorPubKey
    path*: KeyPath
    uuid*: string
    version*: int

  KeystoreKind* = enum
    Local, Remote

  RemoteKeystoreFlag* {.pure.} = enum
    IgnoreSSLVerification, DynamicKeystore

  HttpHostUri* = distinct Uri

  RemoteSignerInfo* = object
    url*: HttpHostUri
    id*: uint32
    pubkey*: ValidatorPubKey

  FileLockHandle* = ref object
    ioHandle*: IoLockHandle
    opened*: bool

  RemoteSignerType* {.pure.} = enum
    Web3Signer, VerifyingWeb3Signer

  ProvenProperty* = object
    path*: string
    description*: Option[string]
    phase0Index*: Option[GeneralizedIndex]
    altairIndex*: Option[GeneralizedIndex]
    bellatrixIndex*: Option[GeneralizedIndex]
    capellaIndex*: Option[GeneralizedIndex]
    denebIndex*: Option[GeneralizedIndex]

  KeystoreData* = object
    version*: uint64
    pubkey*: ValidatorPubKey
    description*: Option[string]
    handle*: FileLockHandle
    case kind*: KeystoreKind
    of KeystoreKind.Local:
      privateKey*: ValidatorPrivKey
      path*: KeyPath
      uuid*: string
    of KeystoreKind.Remote:
      flags*: set[RemoteKeystoreFlag]
      remotes*: seq[RemoteSignerInfo]
      threshold*: uint32
      case remoteType*: RemoteSignerType
      of RemoteSignerType.Web3Signer:
        discard
      of RemoteSignerType.VerifyingWeb3Signer:
        provenBlockProperties*: seq[ProvenProperty]

  NetKeystore* = object
    crypto*: Crypto
    description*: Option[string]
    pubkey*: lcrypto.PublicKey
    uuid*: string
    version*: int

  RemoteKeystore* = object
    version*: uint64
    description*: Option[string]
    case remoteType*: RemoteSignerType
    of RemoteSignerType.Web3Signer:
      discard
    of RemoteSignerType.VerifyingWeb3Signer:
      provenBlockProperties*: seq[ProvenProperty]
    pubkey*: ValidatorPubKey
    flags*: set[RemoteKeystoreFlag]
    remotes*: seq[RemoteSignerInfo]
    threshold*: uint32

  KsResult*[T] = Result[T, string]

  Eth2KeyKind* = enum
    signingKeyKind # Also known as voting key
    withdrawalKeyKind

  UUID* = distinct string
  WalletName* = distinct string
  Mnemonic* = distinct string
  KeyPath* = distinct string
  KeySeed* = distinct seq[byte]
  KeystorePass* = object
    str*: string

  Credentials* = object
    mnemonic*: Mnemonic
    keystore*: Keystore
    signingKey*: ValidatorPrivKey
    withdrawalKey*: ValidatorPrivKey

  SimpleHexEncodedTypes* = ScryptSalt|ChecksumBytes|CipherBytes

  CacheItemFlag {.pure.} = enum
    Missing, Present

  KeystoreCacheItem = object
    flag: CacheItemFlag
    kdf: Kdf
    cipher: Cipher
    decryptionKey: seq[byte]
    timestamp: Moment

  KdfSaltKey* = distinct array[32, byte]

  KeystoreCache* = object
    expireTime*: Duration
    table*: Table[KdfSaltKey, KeystoreCacheItem]

  KeystoreCacheRef* = ref KeystoreCache

const
  keyLen = 32

  scryptParams = ScryptParams(
    dklen: uint64 keyLen,
    n: 2^18,
    p: 1,
    r: 8
  )

  pbkdf2Params = Pbkdf2Params(
    dklen: uint64 keyLen,
    c: uint64(2^18),
    prf: HmacSha256
  )

  # https://eips.ethereum.org/EIPS/eip-2334
  eth2KeyPurpose = 12381
  eth2CoinType* = 3600
  baseKeyPath* = [Natural eth2KeyPurpose, eth2CoinType]

  # https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
  wordListLen = 2048
  maxWordLen = 16

  KeystoreCachePruningTime* = 5.minutes

UUID.serializesAsBaseIn Json
KeyPath.serializesAsBaseIn Json
WalletName.serializesAsBaseIn Json

ChecksumFunctionKind.serializesAsTextInJson
CipherFunctionKind.serializesAsTextInJson
PrfKind.serializesAsTextInJson
KdfKind.serializesAsTextInJson

template `$`*(u: HttpHostUri): string =
  `$`(Uri(u))

template `==`*(lhs, rhs: HttpHostUri): bool =
  Uri(lhs) == Uri(rhs)

template `<`*(lhs, rhs: HttpHostUri): bool =
  $Uri(lhs) < $Uri(rhs)

template `$`*(m: Mnemonic): string =
  string(m)

template `==`*(lhs, rhs: WalletName): bool =
  string(lhs) == string(rhs)

template `$`*(x: WalletName): string =
  string(x)

# TODO: `burnMem` in nimcrypto could use distinctBase
#       to make its usage less error-prone.
template burnMem*(m: var (Mnemonic|string)) =
  ncrutils.burnMem(string m)

template burnMem*(m: var KeySeed) =
  ncrutils.burnMem(distinctBase m)

template burnMem*(m: var KeystorePass) =
  ncrutils.burnMem(m.str)

func longName*(wallet: Wallet): string =
  if wallet.name.string == wallet.uuid.string:
    wallet.name.string
  else:
    wallet.name.string & " (" & wallet.uuid.string & ")"

macro wordListArray*(filename: static string,
                     maxWords: static int = 0,
                     minWordLen: static int = 0,
                     maxWordLen: static int = high(int)): untyped =
  result = newTree(nnkBracket)
  let words = slurp(filename.replace('\\', '/')).splitLines()
  for word in words:
    if word.len >= minWordLen and word.len <= maxWordLen:
      result.add newCall("cstring", newLit(word))
      if maxWords > 0 and result.len >= maxWords:
        return

const
  englishWords = wordListArray("english_word_list.txt",
                                maxWords = wordListLen,
                                maxWordLen = maxWordLen)
  englishWordsDigest =
    "AD90BF3BEB7B0EB7E5ACD74727DC0DA96E0A280A258354E7293FB7E211AC03DB".toDigest

proc checkEnglishWords(): bool =
  if len(englishWords) != wordListLen:
    false
  else:
    var ctx: sha256
    ctx.init()
    for item in englishWords:
      ctx.update($item)
    ctx.finish() == englishWordsDigest

static:
  doAssert(checkEnglishWords(), "English words array is corrupted!")

func validateKeyPath*(path: string): Result[KeyPath, cstring] =
  var digitCount: int
  var number: BiggestUInt
  try:
    for elem in path.string.split("/"):
      # TODO: doesn't "m" have to be the first character and is it the only
      # place where it is valid?
      if elem == "m":
        continue
      # parseBiggestUInt can raise if overflow
      digitCount = elem.parseBiggestUInt(number)
      if digitCount == 0:
        return err("Invalid derivation path")
  except ValueError:
    return err("KeyPath contains invalid number(s)")

  return ok(KeyPath path)

iterator pathNodes(path: KeyPath): Natural =
  # TODO: we have exceptions there
  # and this iterator is used to derive secret keys
  # if we fail we want to scrub secrets from memory
  try:
    for elem in path.string.split("/"):
      if elem == "m": continue
      yield parseBiggestUInt(elem)
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

func isControlRune(r: Rune): bool =
  let r = int r
  (r >= 0 and r < 0x20) or (r >= 0x7F and r < 0xA0)

proc init*(T: type KeystorePass, input: string): T =
  for rune in toNFKD(input):
    if not isControlRune(rune):
      result.str.add rune

func getSeed*(mnemonic: Mnemonic, password: KeystorePass): KeySeed =
  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
  let salt = toNFKD("mnemonic" & password.str)
  KeySeed sha512.pbkdf2(mnemonic.string, salt, 2048, 64)

template add(m: var Mnemonic, s: cstring) =
  m.string.add s

proc generateMnemonic*(
    rng: var HmacDrbgContext,
    words: openArray[cstring] = englishWords,
    entropyParam: openArray[byte] = @[]): Mnemonic =
  ## Generates a valid BIP-0039 mnenomic:
  ## https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
  var entropy =
    if entropyParam.len == 0:
      rng.generateBytes(32)
    else:
      doAssert entropyParam.len >= 128 and
               entropyParam.len <= 256 and
               entropyParam.len mod 32 == 0
      @entropyParam

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

proc validateMnemonic*(inputWords: string,
                       outputMnemonic: var Mnemonic): bool =
  ## Accept a case-insensitive input string and returns `true`
  ## if it represents a valid mnenomic. The `outputMnemonic`
  ## value will be populated with a normalized lower-case
  ## version of the mnemonic using a single space separator.
  ##
  ## The `outputMnemonic` value may be populated partially
  ## with sensitive data even in case of validator failure.
  ## Make sure to burn the received data after usage.

  # TODO consider using a SecretString type for inputWords

  let words = strutils.strip(inputWords.string.toNFKD).split(Whitespace)
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

proc deriveChildKey*(masterKey: ValidatorPrivKey,
                     path: openArray[Natural]): ValidatorPrivKey =
  result = masterKey
  for idx in path:
    # TODO: we have exceptions in pathNodes unless `validateKeyPath`
    # was called,
    # and this iterator is used to derive secret keys
    # if we fail we want to scrub secrets from memory
    result = deriveChildKey(result, idx)

proc keyFromPath*(mnemonic: Mnemonic,
                  password: KeystorePass,
                  path: KeyPath): ValidatorPrivKey =
  deriveChildKey(deriveMasterKey(mnemonic, password), path)

proc shaChecksum(key, cipher: openArray[byte]): Sha256Digest =
  var ctx: sha256
  ctx.init()
  ctx.update(key)
  ctx.update(cipher)
  result = ctx.finish()
  ctx.clear()

proc writeJsonHexString(s: OutputStream, data: openArray[byte])
                       {.raises: [IOError].} =
  s.write '"'
  s.write ncrutils.toHex(data, {HexFlags.LowerCase})
  s.write '"'

proc readValue*(r: var JsonReader, value: var Pbkdf2Salt)
               {.raises: [SerializationError, IOError].} =
  let s = r.readValue(string)

  if s.len == 0 or s.len mod 16 != 0:
    r.raiseUnexpectedValue(
      "The Pbkdf2Salt salt must have a non-zero length divisible by 16")

  value = Pbkdf2Salt ncrutils.fromHex(s)
  let length = len(seq[byte](value))
  if length == 0 or (length mod 8) != 0:
    r.raiseUnexpectedValue(
      "The Pbkdf2Salt must be a valid hex string")

proc readValue*(r: var JsonReader, value: var Aes128CtrIv)
               {.raises: [SerializationError, IOError].} =
  let s = r.readValue(string)

  if s.len != 32:
    r.raiseUnexpectedValue(
      "The aes-128-ctr IV must be a string of length 32")

  value = Aes128CtrIv ncrutils.fromHex(s)
  if len(seq[byte](value)) != 16:
    r.raiseUnexpectedValue(
      "The aes-128-ctr IV must be a valid hex string")

proc readValue*[T: SimpleHexEncodedTypes](r: var JsonReader, value: var T) {.
     raises: [SerializationError, IOError].} =
  value = T ncrutils.fromHex(r.readValue(string))
  if len(seq[byte](value)) == 0:
    r.raiseUnexpectedValue("Valid hex string expected")

template readValueImpl(r: var JsonReader, value: var Checksum) =
  var
    functionSpecified = false
    paramsSpecified = false
    messageSpecified = false

  for fieldName in readObjectFields(r):
    case fieldName
    of "function":
      value = Checksum(function: r.readValue(ChecksumFunctionKind))
      functionSpecified = true

    of "params":
      if functionSpecified:
        case value.function
        of sha256Checksum:
          r.readValue(value.params)
      else:
        r.raiseUnexpectedValue(
          "The 'params' field must be specified after the 'function' field")
      paramsSpecified = true

    of "message":
      if functionSpecified:
        case value.function
        of sha256Checksum:
          r.readValue(value.message)
      else:
        r.raiseUnexpectedValue(
          "The 'message' field must be specified after the 'function' field")
      messageSpecified = true

    else:
      r.raiseUnexpectedField(fieldName, "Checksum")

  if not (functionSpecified and paramsSpecified and messageSpecified):
    r.raiseUnexpectedValue(
      "The Checksum value should have sub-fields named " &
      "'function', 'params', and 'message'")

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22060
proc readValue*(r: var JsonReader[DefaultFlavor], value: var Checksum)
    {.raises: [SerializationError, IOError].} =
  readValueImpl(r, value)
{.pop.}

template readValueImpl(r: var JsonReader, value: var Cipher) =
  var
    functionSpecified = false
    paramsSpecified = false
    messageSpecified = false

  for fieldName in readObjectFields(r):
    case fieldName
    of "function":
      value = Cipher(
        function: r.readValue(CipherFunctionKind), message: value.message)
      functionSpecified = true

    of "params":
      if functionSpecified:
        case value.function
        of aes128CtrCipher:
          r.readValue(value.params)
      else:
        r.raiseUnexpectedValue(
          "The 'params' field must be specified after the 'function' field")
      paramsSpecified = true

    of "message":
      r.readValue(value.message)
      messageSpecified = true

    else:
      r.raiseUnexpectedField(fieldName, "Cipher")

  if not (functionSpecified and paramsSpecified and messageSpecified):
    r.raiseUnexpectedValue(
      "The Cipher value should have sub-fields named " &
      "'function', 'params', and 'message'")

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22060
proc readValue*(r: var JsonReader[DefaultFlavor], value: var Cipher)
    {.raises: [SerializationError, IOError].} =
  readValueImpl(r, value)
{.pop.}

template readValueImpl(r: var JsonReader, value: var Kdf) =
  var
    functionSpecified = false
    paramsSpecified = false

  for fieldName in readObjectFields(r):
    case fieldName
    of "function":
      value = Kdf(function: r.readValue(KdfKind), message: value.message)
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

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22060
proc readValue*(r: var JsonReader[DefaultFlavor], value: var Kdf)
    {.raises: [SerializationError, IOError].} =
  readValueImpl(r, value)
{.pop.}

proc readValue*(r: var JsonReader, value: var (Checksum|Cipher|Kdf)) =
  static: raiseAssert "Unknown flavor `JsonReader[" & $typeof(r).Flavor &
    "]` for `readValue` of `" & $typeof(value) & "`"

# HttpHostUri
proc readValue*(reader: var JsonReader, value: var HttpHostUri) {.
     raises: [IOError, SerializationError].} =
  let svalue = reader.readValue(string)
  let res = parseUri(svalue)
  if res.scheme != "http" and res.scheme != "https":
    reader.raiseUnexpectedValue("Incorrect URL scheme")
  if len(res.hostname) == 0:
    reader.raiseUnexpectedValue("Missing URL hostname")
  value = HttpHostUri(res)

proc writeValue*(
    writer: var JsonWriter, value: HttpHostUri) {.raises: [IOError].} =
  writer.writeValue($distinctBase(value))

# RemoteKeystore
proc writeValue*(
    writer: var JsonWriter, value: RemoteKeystore) {.raises: [IOError].} =
  writer.beginRecord()
  writer.writeField("version", value.version)
  writer.writeField("pubkey", "0x" & value.pubkey.toHex())
  writer.writeField("remotes", value.remotes)
  writer.writeField("threshold", value.threshold)
  case value.remoteType
  of RemoteSignerType.Web3Signer:
    writer.writeField("type", "web3signer")
  of RemoteSignerType.VerifyingWeb3Signer:
    writer.writeField("type", "verifying-web3signer")
    writer.writeField("proven_block_properties", value.provenBlockProperties)
  if value.description.isSome():
    writer.writeField("description", value.description.get())
  if RemoteKeystoreFlag.IgnoreSSLVerification in value.flags:
    writer.writeField("ignore_ssl_verification", true)
  writer.endRecord()

template writeValue*(w: var JsonWriter,
                     value: Pbkdf2Salt|SimpleHexEncodedTypes|Aes128CtrIv) =
  writeJsonHexString(w.stream, distinctBase value)

func parseProvenBlockProperty*(propertyPath: string): Result[ProvenProperty, string] =
  if propertyPath == ".execution_payload.fee_recipient":
    ok ProvenProperty(
      path: propertyPath,
      bellatrixIndex: some GeneralizedIndex(401),
      capellaIndex: some GeneralizedIndex(401),
      denebIndex: some GeneralizedIndex(801))
  elif propertyPath == ".graffiti":
    ok ProvenProperty(
      path: propertyPath,
      # TODO: graffiti is present since genesis, so the correct index in the early
      #       forks can be supplied here
      bellatrixIndex: some GeneralizedIndex(18),
      capellaIndex: some GeneralizedIndex(18),
      denebIndex: some GeneralizedIndex(18))
  else:
    err("Keystores with proven properties different than " &
        "`.execution_payload.fee_recipient` and `.graffiti` " &
        "require a more recent version of Nimbus")

proc readValue*(reader: var JsonReader, value: var RemoteKeystore)
               {.raises: [SerializationError, IOError].} =
  var
    version: Option[uint64]
    description: Option[string]
    remote: Option[HttpHostUri]
    remotes: Option[seq[RemoteSignerInfo]]
    remoteType: Option[RemoteSignerType]
    provenBlockProperties: Option[seq[ProvenProperty]]
    ignoreSslVerification: Option[bool]
    pubkey: Option[ValidatorPubKey]
    threshold: Option[uint32]

  # TODO: implementing deserializers for versioned objects
  #       manually is extremely error-prone. This should use
  #       the auto-generated deserializer from nim-json-serialization
  for fieldName in readObjectFields(reader):
    case fieldName:
    of "pubkey":
      if pubkey.isSome:
        reader.raiseUnexpectedField("Multiple `pubkey` fields found",
                                    "RemoteKeystore")
      pubkey = some(reader.readValue(ValidatorPubKey))
    of "remote":
      if remote.isSome:
        reader.raiseUnexpectedField("Multiple `remote` fields found",
                                    "RemoteKeystore")
      if remotes.isSome:
        reader.raiseUnexpectedField("The `remote` field cannot be specified together with `remotes`",
                                    "RemoteKeystore")
      remote = some(reader.readValue(HttpHostUri))
    of "remotes":
      if remotes.isSome:
        reader.raiseUnexpectedField("Multiple `remote` fields found",
                                    "RemoteKeystore")
      if remote.isSome:
        reader.raiseUnexpectedField("The `remotes` field cannot be specified together with `remote`",
                                    "RemoteKeystore")
      if version.isNone:
        reader.raiseUnexpectedField(
          "The `remotes` field should be specified after the `version` field of the keystore",
          "RemoteKeystore")
      if version.get < 2:
        reader.raiseUnexpectedField(
          "The `remotes` field is valid only past version 2 of the remote keystore format",
          "RemoteKeystore")
      remotes = some(reader.readValue(seq[RemoteSignerInfo]))
    of "version":
      if version.isSome:
        reader.raiseUnexpectedField("Multiple `version` fields found",
                                    "RemoteKeystore")
      version = some(reader.readValue(uint64))
      if version.get > 3'u64:
        reader.raiseUnexpectedValue(
          "Remote keystore version " & $version.get &
          " requires a more recent version of Nimbus")
    of "description":
      if description.isSome:
        reader.raiseUnexpectedField("Multiple `description` fields found",
                                    "RemoteKeystore")
      description = some(reader.readValue(string))
    of "ignore_ssl_verification":
      if ignoreSslVerification.isSome:
        reader.raiseUnexpectedField("Multiple conflicting options found",
                                    "RemoteKeystore")
      ignoreSslVerification = some(reader.readValue(bool))
    of "type":
      if remoteType.isSome:
        reader.raiseUnexpectedField("Multiple `type` fields found",
                                    "RemoteKeystore")
      let remoteTypeValue = case reader.readValue(string).toLowerAscii()
        of "web3signer":
          RemoteSignerType.Web3Signer
        of "verifying-web3signer":
          RemoteSignerType.VerifyingWeb3Signer
        else:
          reader.raiseUnexpectedValue("Unsupported remote signer `type` value")
      remoteType = some remoteTypeValue
    of "proven_block_properties":
      if provenBlockProperties.isSome:
        reader.raiseUnexpectedField("Multiple `proven_block_properties` fields found",
                                    "RemoteKeystore")
      if version.isNone:
        reader.raiseUnexpectedField(
          "The `proven_block_properties` field should be specified after the `version` field of the keystore",
          "RemoteKeystore")
      if version.get < 3:
        reader.raiseUnexpectedField(
          "The `proven_block_properties` field is valid only past version 3 of the remote keystore format",
          "RemoteKeystore")
      if remoteType.isNone:
        reader.raiseUnexpectedField(
          "The `proven_block_properties` field should be specified after the `type` field of the keystore",
          "RemoteKeystore")
      if remoteType.get != RemoteSignerType.VerifyingWeb3Signer:
        reader.raiseUnexpectedField(
          "The `proven_block_properties` field can be specified only when the remote signer type is 'verifying-web3signer'",
          "RemoteKeystore")
      var provenProperties = reader.readValue(seq[ProvenProperty])
      for prop in provenProperties.mitems:
        if prop.path == ".execution_payload.fee_recipient":
          prop.bellatrixIndex = some GeneralizedIndex(401)
          prop.capellaIndex = some GeneralizedIndex(401)
          prop.denebIndex = some GeneralizedIndex(801)
        elif prop.path == ".graffiti":
          # TODO: graffiti is present since genesis, so the correct index in the early
          #       forks can be supplied here
          prop.bellatrixIndex = some GeneralizedIndex(18)
          prop.capellaIndex = some GeneralizedIndex(18)
          prop.denebIndex = some GeneralizedIndex(18)
        else:
          reader.raiseUnexpectedValue("Keystores with proven properties different than " &
                                      "`.execution_payload.fee_recipient` and `.graffiti` " &
                                      "require a more recent version of Nimbus")
      provenBlockProperties = some provenProperties
    of "threshold":
      if threshold.isSome:
        reader.raiseUnexpectedField("Multiple `threshold` fields found",
                                    "RemoteKeystore")
      if version.isNone:
        reader.raiseUnexpectedField(
          "The `threshold` field should be specified after the `version` field of the keystore",
          "RemoteKeystore")
      if version.get < 2:
        reader.raiseUnexpectedField(
          "The `threshold` field is valid only past version 2 of the remote keystore format",
          "RemoteKeystore")
      threshold = some(reader.readValue(uint32))
    else:
      # Ignore unknown field names.
      discard

  if version.isNone():
    reader.raiseUnexpectedValue("The required field `version` is missing")
  if remotes.isNone():
    if remote.isSome and pubkey.isSome:
      remotes = some @[RemoteSignerInfo(
        pubkey: pubkey.get,
        id: 0,
        url: remote.get
      )]
    else:
      reader.raiseUnexpectedValue("The required field `remotes` is missing")

  if threshold.isNone:
    if remotes.get.len > 1:
      reader.raiseUnexpectedValue("The `threshold` field must be specified when using distributed keystores")
  else:
    if threshold.get.uint64 > remotes.get.lenu64:
      reader.raiseUnexpectedValue("The specified `threshold` must be lower than the number of remote signers")

  if pubkey.isNone():
    reader.raiseUnexpectedValue("Field `pubkey` is missing")

  if version.get >= 3:
    if remoteType.isNone:
      reader.raiseUnexpectedValue("The required field `type` is missing")
    case remoteType.get
    of RemoteSignerType.Web3Signer:
      discard
    of RemoteSignerType.VerifyingWeb3Signer:
      if provenBlockProperties.isNone:
        reader.raiseUnexpectedValue("The required field `proven_block_properties` is missing")

  value = case remoteType.get(RemoteSignerType.Web3Signer)
    of RemoteSignerType.Web3Signer:
      RemoteKeystore(
        version: 2'u64,
        pubkey: pubkey.get,
        description: description,
        remoteType: RemoteSignerType.Web3Signer,
        remotes: remotes.get,
        threshold: threshold.get(1))
    of RemoteSignerType.VerifyingWeb3Signer:
      RemoteKeystore(
        version: 2'u64,
        pubkey: pubkey.get,
        description: description,
        remoteType: RemoteSignerType.VerifyingWeb3Signer,
        provenBlockProperties: provenBlockProperties.get,
        remotes: remotes.get,
        threshold: threshold.get(1))

template bytes(value: Pbkdf2Salt|SimpleHexEncodedTypes|Aes128CtrIv): seq[byte] =
  distinctBase value

func scrypt(password: openArray[char], salt: openArray[byte],
            N, r, p: int; keyLen: static[int]): array[keyLen, byte] =
  let (xyvLen, bLen) = scryptCalc(N, r, p)
  var xyv = newSeq[uint32](xyvLen)
  var b = newSeq[byte](bLen)
  discard scrypt(password, salt, N, r, p, xyv, b, result)

func areValid(params: Pbkdf2Params): bool =
  if params.c == 0 or params.dklen < 32 or params.salt.bytes.len == 0:
    return false

  # https://www.ietf.org/rfc/rfc2898.txt
  let hLen = case params.prf
    of HmacSha256: 256 / 8
  params.dklen <= high(uint32).uint64 * hLen.uint64

func areValid(params: ScryptParams): bool =
  static: doAssert scryptParams.dklen >= 32

  params.dklen == scryptParams.dklen and
  params.n == scryptParams.n and
  params.r == scryptParams.r and
  params.p == scryptParams.p and
  params.salt.bytes.len > 0

proc decryptCryptoField*(crypto: Crypto, decKey: openArray[byte],
                         outSecret: var seq[byte]): DecryptionStatus =
  if crypto.cipher.message.bytes.len == 0:
    return DecryptionStatus.InvalidKeystore
  if len(decKey) < keyLen:
    return DecryptionStatus.InvalidKeystore
  let valid =
    case crypto.checksum.function
    of sha256Checksum:
      template params: auto {.used.} = crypto.checksum.params
      template message: auto = crypto.checksum.message
      message == shaChecksum(decKey.toOpenArray(16, 31),
                             crypto.cipher.message.bytes)
  if not valid:
    return DecryptionStatus.InvalidPassword

  case crypto.cipher.function
  of aes128CtrCipher:
    template params: auto = crypto.cipher.params
    var aesCipher: CTR[aes128]
    outSecret.setLen(crypto.cipher.message.bytes.len)
    aesCipher.init(decKey.toOpenArray(0, 15), params.iv.bytes)
    aesCipher.decrypt(crypto.cipher.message.bytes, outSecret)
    aesCipher.clear()
  DecryptionStatus.Success

proc getDecryptionKey*(crypto: Crypto, password: KeystorePass,
                       decKey: var seq[byte]): DecryptionStatus =
  let res =
    case crypto.kdf.function
    of kdfPbkdf2:
      template params: auto = crypto.kdf.pbkdf2Params
      if not params.areValid or params.c > high(int).uint64:
        return DecryptionStatus.InvalidKeystore
      Eth2DigestCtx.pbkdf2(password.str, params.salt.bytes, int(params.c),
                           int(params.dklen))
    of kdfScrypt:
      template params: auto = crypto.kdf.scryptParams
      if not params.areValid:
        return DecryptionStatus.InvalidKeystore
      @(scrypt(password.str, params.salt.bytes, scryptParams.n,
               scryptParams.r, scryptParams.p, int(scryptParams.dklen)))
  decKey = res
  DecryptionStatus.Success

proc decryptCryptoField*(crypto: Crypto,
                         password: KeystorePass,
                         outSecret: var seq[byte]): DecryptionStatus =
  # https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
  var decKey: seq[byte]
  if crypto.cipher.message.bytes.len == 0:
    return InvalidKeystore

  let res = getDecryptionKey(crypto, password, decKey)
  if res != DecryptionStatus.Success:
    return res

  decryptCryptoField(crypto, decKey, outSecret)

func cstringToStr(v: cstring): string = $v

template parseKeystore*(jsonContent: string): Keystore =
  Json.decode(jsonContent, Keystore,
              requireAllFields = true,
              allowUnknownFields = true)

template parseNetKeystore*(jsonContent: string): NetKeystore =
  Json.decode(jsonContent, NetKeystore,
              requireAllFields = true,
              allowUnknownFields = true)

template parseRemoteKeystore*(jsonContent: string): RemoteKeystore =
  Json.decode(jsonContent, RemoteKeystore,
              requireAllFields = false,
              allowUnknownFields = true)

proc getSaltKey(keystore: Keystore, password: KeystorePass): KdfSaltKey =
  let digest =
    case keystore.crypto.kdf.function
    of kdfPbkdf2:
      template params: auto = keystore.crypto.kdf.pbkdf2Params
      withEth2Hash:
        h.update(seq[byte](params.salt))
        h.update(password.str.toOpenArrayByte(0, len(password.str) - 1))
        h.update(toBytesLE(params.dklen))
        h.update(toBytesLE(params.c))
        let prf = $params.prf
        h.update(prf.toOpenArrayByte(0, len(prf) - 1))
    of kdfScrypt:
      template params: auto = keystore.crypto.kdf.scryptParams
      withEth2Hash:
        h.update(seq[byte](params.salt))
        h.update(password.str.toOpenArrayByte(0, len(password.str) - 1))
        h.update(toBytesLE(params.dklen))
        h.update(toBytesLE(uint64(params.n)))
        h.update(toBytesLE(uint64(params.p)))
        h.update(toBytesLE(uint64(params.r)))
  KdfSaltKey(digest.data)

proc `==`*(a, b: KdfSaltKey): bool {.borrow.}
proc hash*(salt: KdfSaltKey): Hash {.borrow.}

{.push warning[ProveField]:off.}
func `==`*(a, b: Kdf): bool =
  # We do not care about `message` field.
  if a.function != b.function:
    return false
  case a.function
  of kdfPbkdf2:
    template aparams: auto = a.pbkdf2Params
    template bparams: auto = b.pbkdf2Params
    (aparams.dklen == bparams.dklen) and (aparams.c == bparams.c) and
    (aparams.prf == bparams.prf) and (len(seq[byte](aparams.salt)) > 0) and
    (seq[byte](aparams.salt) == seq[byte](bparams.salt))
  of kdfScrypt:
    template aparams: auto = a.scryptParams
    template bparams: auto = b.scryptParams
    (aparams.dklen == bparams.dklen) and (aparams.n == bparams.n) and
    (aparams.p == bparams.p) and (aparams.r == bparams.r) and
    (len(seq[byte](aparams.salt)) > 0) and
    (seq[byte](aparams.salt) == seq[byte](bparams.salt))
{.pop.}

func `==`*(a, b: Cipher): bool =
  # We do not care about `params` and `message` fields.
  a.function == b.function

func `==`*(a, b: KeystoreCacheItem): bool =
  (a.kdf == b.kdf) and (a.cipher == b.cipher) and
  (a.decryptionKey == b.decryptionKey)

func init*(t: typedesc[KeystoreCacheRef],
           expireTime = KeystoreCachePruningTime): KeystoreCacheRef =
  KeystoreCacheRef(
    table: initTable[KdfSaltKey, KeystoreCacheItem](),
    expireTime: expireTime
  )

proc clear*(cache: KeystoreCacheRef) =
  cache.table.clear()

proc pruneExpiredKeys*(cache: KeystoreCacheRef) =
  if cache.expireTime == InfiniteDuration:
    return
  let currentTime = Moment.now()
  var keys: seq[KdfSaltKey]
  for key, value in cache.table.mpairs():
    if currentTime - value.timestamp >= cache.expireTime:
      keys.add(key)
      burnMem(value.decryptionKey)
  for item in keys:
    cache.table.del(item)

proc init*(t: typedesc[KeystoreCacheItem], keystore: Keystore,
           key: openArray[byte]): KeystoreCacheItem =
  KeystoreCacheItem(flag: CacheItemFlag.Present, kdf: keystore.crypto.kdf,
                    cipher: keystore.crypto.cipher, decryptionKey: @key,
                    timestamp: Moment.now())

proc getCachedKey*(cache: KeystoreCacheRef,
                   keystore: Keystore, password: KeystorePass): Opt[seq[byte]] =
  if isNil(cache): return Opt.none(seq[byte])
  let
    saltKey = keystore.getSaltKey(password)
    item = cache.table.getOrDefault(saltKey)
  case item.flag
  of CacheItemFlag.Present:
    if (item.kdf == keystore.crypto.kdf) and
       (item.cipher == keystore.crypto.cipher):
      Opt.some(item.decryptionKey)
    else:
      Opt.none(seq[byte])
  else:
    Opt.none(seq[byte])

proc setCachedKey*(cache: KeystoreCacheRef, keystore: Keystore,
                   password: KeystorePass, key: openArray[byte]) =
  if isNil(cache): return
  let saltKey = keystore.getSaltKey(password)
  cache.table[saltKey] = KeystoreCacheItem.init(keystore, key)

proc destroyCacheKey*(cache: KeystoreCacheRef,
                      keystore: Keystore, password: KeystorePass) =
  if isNil(cache): return
  let saltKey = keystore.getSaltKey(password)
  cache.table.withValue(saltKey, item):
    burnMem(item[].decryptionKey)
  cache.table.del(saltKey)

proc decryptKeystore*(keystore: Keystore,
                      password: KeystorePass,
                      cache: KeystoreCacheRef): KsResult[ValidatorPrivKey] =
  var secret: seq[byte]
  defer: burnMem(secret)

  while true:
    let res = cache.getCachedKey(keystore, password)
    if res.isNone():
      var decKey: seq[byte]
      defer: burnMem(decKey)

      let kres = getDecryptionKey(keystore.crypto, password, decKey)
      if kres != DecryptionStatus.Success:
        return err($kres)
      let dres = decryptCryptoField(keystore.crypto, decKey, secret)
      if dres != DecryptionStatus.Success:
        return err($dres)
      cache.setCachedKey(keystore, password, decKey)
      break
    else:
      var decKey = res.get()
      defer: burnMem(decKey)

      let dres = decryptCryptoField(keystore.crypto, decKey, secret)
      if dres == DecryptionStatus.Success:
        break

      cache.destroyCacheKey(keystore, password)

  ValidatorPrivKey.fromRaw(secret).mapErr(cstringToStr)

proc decryptKeystore*(keystore: JsonString,
                      password: KeystorePass,
                      cache: KeystoreCacheRef): KsResult[ValidatorPrivKey] =
  let keystore =
    try:
      parseKeystore(string(keystore))
    except SerializationError as e:
      return err(e.formatMsg("<keystore>"))

  decryptKeystore(keystore, password, cache)

proc decryptKeystore*(keystore: Keystore,
                      password: KeystorePass): KsResult[ValidatorPrivKey] =
  decryptKeystore(keystore, password, nil)

proc decryptKeystore*(keystore: JsonString,
                      password: KeystorePass): KsResult[ValidatorPrivKey] =
  decryptKeystore(keystore, password, nil)

proc writeValue*(
    writer: var JsonWriter, value: lcrypto.PublicKey
) {.inline, raises: [IOError].} =
  writer.writeValue(ncrutils.toHex(value.getBytes().get(),
                                   {HexFlags.LowerCase}))

proc readValue*(reader: var JsonReader, value: var lcrypto.PublicKey) {.
     raises: [SerializationError, IOError].} =
  let res = init(lcrypto.PublicKey, reader.readValue(string))
  if res.isOk():
    value = res.get()
  else:
    # TODO: Can we provide better diagnostic?
    raiseUnexpectedValue(reader, "Valid hex-encoded public key expected")

proc decryptNetKeystore*(nkeystore: NetKeystore,
                         password: KeystorePass): KsResult[lcrypto.PrivateKey] =
  var secret: seq[byte]
  defer: burnMem(secret)
  let status = decryptCryptoField(nkeystore.crypto, password, secret)
  case status
  of Success:
    let res = lcrypto.PrivateKey.init(secret)
    if res.isOk:
      ok res.get
    else:
      err "Invalid key"
  else:
    err $status

proc decryptNetKeystore*(nkeystore: JsonString,
                         password: KeystorePass): KsResult[lcrypto.PrivateKey] =
  try:
    let keystore = parseNetKeystore(string nkeystore)
    return decryptNetKeystore(keystore, password)
  except SerializationError as exc:
    return err(exc.formatMsg("<keystore>"))

proc generateKeystoreSalt*(rng: var HmacDrbgContext): seq[byte] =
  rng.generateBytes(keyLen)

proc createCryptoField(kdfKind: KdfKind,
                       rng: var HmacDrbgContext,
                       secret: openArray[byte],
                       password = KeystorePass.init "",
                       salt: openArray[byte] = @[],
                       iv: openArray[byte] = @[],
                       mode = Secure): Crypto =
  type AES = aes128

  let kdfSalt =
    if salt.len > 0:
      doAssert salt.len == keyLen
      @salt
    else:
      rng.generateBytes(keyLen)

  let aesIv = if iv.len > 0:
    doAssert iv.len == AES.sizeBlock
    @iv
  else:
    rng.generateBytes(AES.sizeBlock)

  var decKey: seq[byte]
  let kdf = case kdfKind
    of kdfPbkdf2:
      var params = pbkdf2Params
      params.salt = Pbkdf2Salt kdfSalt
      if mode == Fast: params.c = 1
      decKey = sha256.pbkdf2(password.str,
                             kdfSalt,
                             int params.c,
                             int params.dklen)
      Kdf(function: kdfPbkdf2, pbkdf2Params: params, message: "")
    of kdfScrypt:
      var params = scryptParams
      params.salt = ScryptSalt kdfSalt
      if mode == Fast: params.n = 1
      decKey = @(scrypt(password.str, kdfSalt,
                        params.n, params.r, params.p, keyLen))
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

proc createNetKeystore*(kdfKind: KdfKind,
                        rng: var HmacDrbgContext,
                        privKey: lcrypto.PrivateKey,
                        password = KeystorePass.init "",
                        description = "",
                        salt: openArray[byte] = @[],
                        iv: openArray[byte] = @[]): NetKeystore =
  let
    secret = privKey.getBytes().get()
    cryptoField = createCryptoField(kdfKind, rng, secret, password, salt, iv)
    pubkey = privKey.getPublicKey().get()
    uuid = uuidGenerate().expect("Random bytes should be available")

  NetKeystore(
    crypto: cryptoField,
    pubkey: pubkey,
    description: if len(description) > 0: some(description)
                 else: none[string](),
    uuid: $uuid,
    version: 1
  )

proc createKeystore*(kdfKind: KdfKind,
                     rng: var HmacDrbgContext,
                     privKey: ValidatorPrivKey,
                     password = KeystorePass.init "",
                     path = KeyPath "",
                     description = "",
                     salt: openArray[byte] = @[],
                     iv: openArray[byte] = @[],
                     mode = Secure): Keystore =
  let
    secret = privKey.toRaw[^32..^1]
    cryptoField = createCryptoField(kdfKind, rng, secret, password, salt, iv, mode)
    pubkey = privKey.toPubKey()
    uuid = uuidGenerate().expect("Random bytes should be available")

  Keystore(
    crypto: cryptoField,
    pubkey: pubkey.toPubKey(),
    path: path,
    description: if len(description) > 0: some(description)
                 else: none[string](),
    uuid: $uuid,
    version: 4)

proc createRemoteKeystore*(pubKey: ValidatorPubKey, remoteUri: HttpHostUri,
                           version = 1'u64, description = "",
                           remoteType = RemoteSignerType.Web3Signer,
                          flags: set[RemoteKeystoreFlag] = {}): RemoteKeystore =
  let signerInfo = RemoteSignerInfo(
    url: remoteUri,
    pubkey: pubKey,
    id: 0
  )
  RemoteKeystore(
    version: version,
    description: if len(description) > 0: some(description)
                 else: none[string](),
    remoteType: remoteType,
    pubkey: pubKey,
    remotes: @[signerInfo],
    flags: flags
  )

proc createWallet*(kdfKind: KdfKind,
                   rng: var HmacDrbgContext,
                   seed: KeySeed,
                   name = WalletName "",
                   salt: openArray[byte] = @[],
                   iv: openArray[byte] = @[],
                   password = KeystorePass.init "",
                   nextAccount = none(Natural),
                   pretty = true): Wallet =
  let
    uuid = UUID $(uuidGenerate().expect("Random bytes should be available"))
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

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#bls_withdrawal_prefix
func makeWithdrawalCredentials*(k: ValidatorPubKey): Eth2Digest =
  var bytes = eth2digest(k.toRaw())
  bytes.data[0] = BLS_WITHDRAWAL_PREFIX.uint8
  bytes

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/deposit-contract.md#withdrawal-credentials
proc makeWithdrawalCredentials*(k: CookedPubKey): Eth2Digest =
  makeWithdrawalCredentials(k.toPubKey())

proc prepareDeposit*(cfg: RuntimeConfig,
                     withdrawalPubKey: CookedPubKey,
                     signingKey: ValidatorPrivKey, signingPubKey: CookedPubKey,
                     amount = MAX_EFFECTIVE_BALANCE.Gwei): DepositData =
  var res = DepositData(
    amount: amount,
    pubkey: signingPubKey.toPubKey(),
    withdrawal_credentials: makeWithdrawalCredentials(withdrawalPubKey))

  res.signature = get_deposit_signature(cfg, res, signingKey).toValidatorSig()
  return res
