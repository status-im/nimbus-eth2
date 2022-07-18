# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  # Standard library
  std/[algorithm, math, parseutils, strformat, strutils, typetraits, unicode,
       uri],
  # Third-party libraries
  normalize,
  # Status libraries
  stew/[results, bitops2, base10], stew/shims/macros,
  eth/keyfile/uuid, blscurve, json_serialization,
  nimcrypto/[sha2, rijndael, pbkdf2, bcmode, hash, scrypt],
  # Local modules
  libp2p/crypto/crypto as lcrypto,
  ./datatypes/base,  ./signatures

export base, uri

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
    description*: ref string
    pubkey*: ValidatorPubKey
    path*: KeyPath
    uuid*: string
    version*: int

  KeystoreKind* = enum
    Local, Remote

  RemoteKeystoreFlag* {.pure.} = enum
    IgnoreSSLVerification

  HttpHostUri* = distinct Uri

  RemoteSignerInfo* = object
    url*: HttpHostUri
    id*: uint32
    pubkey*: ValidatorPubKey

  KeystoreData* = object
    version*: uint64
    pubkey*: ValidatorPubKey
    description*: Option[string]
    case kind*: KeystoreKind
    of KeystoreKind.Local:
      privateKey*: ValidatorPrivKey
      path*: KeyPath
      uuid*: string
    of KeystoreKind.Remote:
      flags*: set[RemoteKeystoreFlag]
      remotes*: seq[RemoteSignerInfo]
      threshold*: uint32

  NetKeystore* = object
    crypto*: Crypto
    description*: ref string
    pubkey*: lcrypto.PublicKey
    uuid*: string
    version*: int

  RemoteSignerType* {.pure.} = enum
    Web3Signer

  RemoteKeystore* = object
    version*: uint64
    description*: Option[string]
    remoteType*: RemoteSignerType
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
  var words = slurp(filename.replace('\\', '/')).splitLines()
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
                       {.raises: [IOError, Defect].} =
  s.write '"'
  s.write ncrutils.toHex(data, {HexFlags.LowerCase})
  s.write '"'

proc readValue*(r: var JsonReader, value: var Pbkdf2Salt)
               {.raises: [SerializationError, IOError, Defect].} =
  var s = r.readValue(string)

  if s.len == 0 or s.len mod 16 != 0:
    r.raiseUnexpectedValue(
      "The Pbkdf2Salt salt must have a non-zero length divisible by 16")

  value = Pbkdf2Salt ncrutils.fromHex(s)
  let length = len(seq[byte](value))
  if length == 0 or (length mod 8) != 0:
    r.raiseUnexpectedValue(
      "The Pbkdf2Salt must be a valid hex string")

proc readValue*(r: var JsonReader, value: var Aes128CtrIv)
               {.raises: [SerializationError, IOError, Defect].} =
  var s = r.readValue(string)

  if s.len != 32:
    r.raiseUnexpectedValue(
      "The aes-128-ctr IV must be a string of length 32")

  value = Aes128CtrIv ncrutils.fromHex(s)
  if len(seq[byte](value)) != 16:
    r.raiseUnexpectedValue(
      "The aes-128-ctr IV must be a valid hex string")

proc readValue*[T: SimpleHexEncodedTypes](r: var JsonReader, value: var T) {.
     raises: [SerializationError, IOError, Defect].} =
  value = T ncrutils.fromHex(r.readValue(string))
  if len(seq[byte](value)) == 0:
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

# HttpHostUri
proc readValue*(reader: var JsonReader, value: var HttpHostUri) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = parseUri(svalue)
  if res.scheme != "http" and res.scheme != "https":
    reader.raiseUnexpectedValue("Incorrect URL scheme")
  if len(res.hostname) == 0:
    reader.raiseUnexpectedValue("Missing URL hostname")
  value = HttpHostUri(res)

proc writeValue*(writer: var JsonWriter, value: HttpHostUri) {.
     raises: [IOError, Defect].} =
  writer.writeValue($distinctBase(value))

# RemoteKeystore
proc writeValue*(writer: var JsonWriter, value: RemoteKeystore)
                {.raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("version", value.version)
  writer.writeField("pubkey", "0x" & value.pubkey.toHex())
  writer.writeField("remotes", value.remotes)
  writer.writeField("threshold", value.threshold)
  case value.remoteType
  of RemoteSignerType.Web3Signer:
    writer.writeField("type", "web3signer")
  if value.description.isSome():
    writer.writeField("description", value.description.get())
  if RemoteKeystoreFlag.IgnoreSSLVerification in value.flags:
    writer.writeField("ignore_ssl_verification", true)
  writer.endRecord()

template writeValue*(w: var JsonWriter,
                     value: Pbkdf2Salt|SimpleHexEncodedTypes|Aes128CtrIv) =
  writeJsonHexString(w.stream, distinctBase value)

proc readValue*(reader: var JsonReader, value: var RemoteKeystore)
               {.raises: [SerializationError, IOError, Defect].} =
  var
    version: Option[uint64]
    description: Option[string]
    remote: Option[HttpHostUri]
    remotes: Option[seq[RemoteSignerInfo]]
    remoteType: Option[string]
    ignoreSslVerification: Option[bool]
    pubkey: Option[ValidatorPubKey]
    threshold: Option[uint32]
    implicitVersion1 = false

  # TODO: implementing deserializers for versioned objects
  #       manually is extremely error-prone. This should use
  #       the auto-generated deserializer from nim-json-serialization
  for fieldName in readObjectFields(reader):
    case fieldName:
    of "pubkey":
      if pubkey.isSome():
        reader.raiseUnexpectedField("Multiple `pubkey` fields found",
                                    "RemoteKeystore")
      pubkey = some(reader.readValue(ValidatorPubKey))
    of "remote":
      if version.isSome and version.get > 1:
        reader.raiseUnexpectedField(
          "The `remote` field is valid only in version 1 of the remote keystore format",
          "RemoteKeystore")

      if remote.isSome():
        reader.raiseUnexpectedField("Multiple `remote` fields found",
                                    "RemoteKeystore")
      remote = some(reader.readValue(HttpHostUri))
      implicitVersion1 = true
    of "remotes":
      if remotes.isSome():
        reader.raiseUnexpectedField("Multiple `remote` fields found",
                                    "RemoteKeystore")
      remotes = some(reader.readValue(seq[RemoteSignerInfo]))
    of "version":
      if version.isSome():
        reader.raiseUnexpectedField("Multiple `version` fields found",
                                    "RemoteKeystore")
      version = some(reader.readValue(uint64))
      if implicitVersion1 and version.get > 1'u64:
        reader.raiseUnexpectedValue(
          "Remote keystore format doesn't match the specified version number")
      if version.get > 2'u64:
        reader.raiseUnexpectedValue(
          "Remote keystore version " & $version.get &
          " requires a more recent version of Nimbus")
    of "description":
      let res = reader.readValue(string)
      if description.isSome():
        description = some(description.get() & "\n" & res)
      else:
        description = some(res)
    of "ignore_ssl_verification":
      if ignoreSslVerification.isSome():
        reader.raiseUnexpectedField("Multiple conflicting options found",
                                    "RemoteKeystore")
      ignoreSslVerification = some(reader.readValue(bool))
    of "type":
      if remoteType.isSome():
        reader.raiseUnexpectedField("Multiple `type` fields found",
                                    "RemoteKeystore")
      remoteType = some(reader.readValue(string))
    of "threshold":
      if threshold.isSome():
        reader.raiseUnexpectedField("Multiple `threshold` fields found",
                                    "RemoteKeystore")
      threshold = some(reader.readValue(uint32))
    else:
      # Ignore unknown field names.
      discard

  if version.isNone():
    reader.raiseUnexpectedValue("Field `version` is missing")
  if remotes.isNone():
    if remote.isSome and pubkey.isSome:
      remotes = some @[RemoteSignerInfo(
        pubkey: pubkey.get,
        id: 0,
        url: remote.get
      )]
    else:
      reader.raiseUnexpectedValue("Field `remotes` is missing")
  if pubkey.isNone():
    reader.raiseUnexpectedValue("Field `pubkey` is missing")

  let keystoreType =
    if remoteType.isSome():
      let res = remoteType.get()
      case res.toLowerAscii()
      of "web3signer":
        RemoteSignerType.Web3Signer
      else:
        reader.raiseUnexpectedValue("Unsupported remote signer `type` value")
    else:
      RemoteSignerType.Web3Signer

  let keystoreFlags =
    block:
      var res: set[RemoteKeystoreFlag]
      if ignoreSslVerification.isSome():
        res.incl(RemoteKeystoreFlag.IgnoreSSLVerification)
      res

  value = RemoteKeystore(
    version: 2'u64,
    pubkey: pubkey.get,
    description: description,
    remoteType: keystoreType,
    remotes: remotes.get,
    threshold: threshold.get(1),
  )

template writeValue*(w: var JsonWriter,
                     value: Pbkdf2Salt|SimpleHexEncodedTypes|Aes128CtrIv) =
  writeJsonHexString(w.stream, distinctBase value)

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

proc decryptCryptoField*(crypto: Crypto,
                         password: KeystorePass,
                         outSecret: var seq[byte]): DecryptionStatus =
  # https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

  if crypto.cipher.message.bytes.len == 0:
    return InvalidKeystore

  let decKey = case crypto.kdf.function
    of kdfPbkdf2:
      template params: auto = crypto.kdf.pbkdf2Params
      if not params.areValid or params.c > high(int).uint64:
        return InvalidKeystore
      sha256.pbkdf2(password.str,
                    params.salt.bytes,
                    int params.c,
                    int params.dklen)
    of kdfScrypt:
      template params: auto = crypto.kdf.scryptParams
      if not params.areValid:
        return InvalidKeystore
      @(scrypt(password.str,
               params.salt.bytes,
               scryptParams.n,
               scryptParams.r,
               scryptParams.p,
               int scryptParams.dklen))

  let derivedChecksum = shaChecksum(decKey.toOpenArray(16, 31),
                                    crypto.cipher.message.bytes)
  if derivedChecksum != crypto.checksum.message:
    return InvalidPassword

  var aesCipher: CTR[aes128]
  outSecret.setLen(crypto.cipher.message.bytes.len)

  aesCipher.init(decKey.toOpenArray(0, 15), crypto.cipher.params.iv.bytes)
  aesCipher.decrypt(crypto.cipher.message.bytes, outSecret)
  aesCipher.clear()

  return Success

func cstringToStr(v: cstring): string = $v

proc decryptKeystore*(keystore: Keystore,
                      password: KeystorePass): KsResult[ValidatorPrivKey] =
  var secret: seq[byte]
  defer: burnMem(secret)
  let status = decryptCryptoField(keystore.crypto, password, secret)
  case status
  of Success:
    ValidatorPrivKey.fromRaw(secret).mapErr(cstringToStr)
  else:
    err $status

proc decryptKeystore*(keystore: JsonString,
                      password: KeystorePass): KsResult[ValidatorPrivKey] =
  let keystore = try: Json.decode(keystore.string, Keystore)
                 except SerializationError as e:
                   return err e.formatMsg("<keystore>")
  decryptKeystore(keystore, password)

proc writeValue*(writer: var JsonWriter, value: lcrypto.PublicKey) {.
     inline, raises: [IOError, Defect].} =
  writer.writeValue(ncrutils.toHex(value.getBytes().get(),
                                   {HexFlags.LowerCase}))

proc readValue*(reader: var JsonReader, value: var lcrypto.PublicKey) {.
     raises: [SerializationError, IOError, Defect].} =
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
    let keystore = Json.decode(string(nkeystore), NetKeystore)
    return decryptNetKeystore(keystore, password)
  except SerializationError as exc:
    return err(exc.formatMsg("<keystore>"))

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
    description: newClone(description),
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
    description: newClone(description),
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

# https://github.com/ethereum/consensus-specs/blob/v0.12.2/specs/phase0/deposit-contract.md#withdrawal-credentials
func makeWithdrawalCredentials*(k: ValidatorPubKey): Eth2Digest =
  var bytes = eth2digest(k.toRaw())
  bytes.data[0] = BLS_WITHDRAWAL_PREFIX.uint8
  bytes

# https://github.com/ethereum/consensus-specs/blob/v0.12.2/specs/phase0/deposit-contract.md#withdrawal-credentials
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
