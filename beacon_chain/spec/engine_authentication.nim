# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[strformat, typetraits],
  stew/[arrayops, base64],
  bearssl/rand,
  chronicles,
  confutils/defs,
  nimcrypto/[hmac, utils, sha2],
  results,
  stew/byteutils

from std/os import `/`, fileExists

export rand, results

const jwtSecretFile* = "jwt.hex"

# https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/authentication.md#key-distribution
# 256-bit shared key
type
  JwtSharedKey* = array[32, byte]
  Rng* = proc(v: var openArray[byte]) {.raises: [], gcsafe.}

func base64urlEncode(x: string): string =
  # The only strings this gets are internally generated, and don't have
  # encoding quirks.
  Base64Url.encode(x.toOpenArrayByte(0, x.high()))

func getIatToken*(time: int64): string =
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/authentication.md#jwt-claims
  # "Required: `iat` (issued-at) claim. The execution layer client **SHOULD**
  # only accept `iat` timestamps which are within +-60 seconds from the current
  # time."
  #
  # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6 describes iat
  # claims.
  #
  # https://pyjwt.readthedocs.io/en/stable/usage.html#issued-at-claim-iat shows
  # an example of an iat claim: {"iat": 1371720939}
  &"""{{"iat":{time}}}"""

func getSignedToken*(key: JwtSharedKey, payload: string): string =
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/authentication.md#jwt-specifications
  # "The execution layer client **MUST** support at least the following `alg`
  # `HMAC + SHA256` (`HS256`)"

  # https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
  # base64urlEncode("""{"typ":"JWT","alg":"HS256"}""") & "."
  const jwsProtectedHeader = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
  # Sanity check
  let signingInput = jwsProtectedHeader & base64urlEncode(payload)

  signingInput & "." & Base64Url.encode(sha256.hmac(key, signingInput).data)

func getSignedIatToken*(key: JwtSharedKey, time: int64): string =
  getSignedToken(key, getIatToken(time))

func parseJwtSharedKey*(input: string): Result[JwtSharedKey, cstring] =
  # Secret JWT key is parsed in constant time using nimcrypto:
  # https://github.com/cheatfate/nimcrypto/pull/44
  try:
    let secret = utils.fromHex(input)
    if secret.len == sizeof(JwtSharedKey):
      ok(JwtSharedKey.initCopyFrom(secret))
    else:
      err("The JWT secret should be 256 bits and hex-encoded")
  except ValueError:
    err("invalid JWT hex string")

proc loadJwtSecretFile*(input: InputFile): Result[JwtSharedKey, cstring] =
  try:
    let lines = readLines(string input, 1)
    if lines.len > 0:
      parseJwtSharedKey(lines[0])
    else:
      err("The JWT token file should not be empty")
  except IOError:
    err("couldn't open specified JWT secret file")

proc checkJwtSecret*(
    rng: Rng, dataDir: string, jwtSecret: Opt[InputFile]
): Result[JwtSharedKey, cstring] =
  # If such a parameter is given, but the file cannot be read, or does not
  # contain a hex-encoded key of 256 bits, the client should treat this as an
  # error: either abort the startup, or show error and continue without
  # exposing the authenticated port.
  if jwtSecret.isNone:
    # If such a parameter is not given, the client SHOULD generate such a
    # token, valid for the duration of the execution, and store the
    # hex-encoded secret as a jwt.hex file on the filesystem.
    #
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.4/src/engine/authentication.md#key-distribution
    let jwtSecretPath = dataDir / jwtSecretFile

    if fileExists(jwtSecretPath):
      # According to the spec:
      # "This file can then be used to provision the counterpart client."
      # Since writing the file is implicit, it stands to reason to interpret the
      # above as reading being implicit too - when execution and consensus
      # clients share the same directory, this allows the setup to "just work".
      return loadJwtSecretFile(InputFile jwtSecretPath)
    var newSecret: JwtSharedKey
    rng(distinctBase newSecret)
    try:
      writeFile(jwtSecretPath, distinctBase(newSecret).to0xHex())
    except IOError as exc:
      # Allow continuing to run, though this is effectively fatal for a merge
      # client using authentication. This keeps it lower-risk initially.
      warn "Could not write JWT secret to data directory", jwtSecretPath, err = exc.msg

    notice "JWT secret generated", jwtSecretPath

    return ok(newSecret)

  loadJwtSecretFile(jwtSecret.get)

proc checkJwtSecret*(
    rng: var HmacDrbgContext, dataDir: string, jwtSecret: Opt[InputFile]
): Result[JwtSharedKey, cstring] =
  let rng = addr rng
  checkJwtSecret(
    proc(v: var openArray[byte]) =
      rng[].generate(v),
    dataDir,
    jwtSecret,
  )
