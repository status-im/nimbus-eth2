# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles, confutils/defs,
  bearssl/rand,
  nimcrypto/[hmac, utils],
  stew/[byteutils, results]

from std/base64 import encode
from std/json import JsonNode, `$`, `%*`
from std/os import `/`
from std/strutils import replace

export rand, results

{.push raises: [].}

const
  JWT_SECRET_LEN = 32

proc base64urlEncode(x: auto): string =
  # The only strings this gets are internally generated, and don't have
  # encoding quirks.
  base64.encode(x, safe = true).replace("=", "")

func getIatToken*(time: int64): JsonNode =
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/authentication.md#jwt-claims
  # "Required: `iat` (issued-at) claim. The execution layer client **SHOULD**
  # only accept `iat` timestamps which are within +-60 seconds from the current
  # time."
  #
  # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6 describes iat
  # claims.
  #
  # https://pyjwt.readthedocs.io/en/stable/usage.html#issued-at-claim-iat shows
  # an example of an iat claim: {"iat": 1371720939}
  %* {"iat": time}

proc getSignedToken*(key: openArray[byte], payload: string): string =
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/authentication.md#jwt-specifications
  # "The execution layer client **MUST** support at least the following `alg`
  # `HMAC + SHA256` (`HS256`)"

  # https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
  const jwsProtectedHeader =
    base64urlEncode($ %* {"typ": "JWT", "alg": "HS256"}) & "."
  # In theory, std/json might change how it encodes, and it doesn't per-se
  # matter but can also simply specify the base64-encoded form directly if
  # useful, since it's never checked here on its own.
  static: doAssert jwsProtectedHeader == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
  let signingInput = jwsProtectedHeader & base64urlEncode(payload)

  signingInput & "." & base64urlEncode(sha256.hmac(key, signingInput).data)

proc getSignedIatToken*(key: openArray[byte], time: int64): string =
  getSignedToken(key, $getIatToken(time))

proc parseJwtTokenValue*(input: string): Result[seq[byte], cstring] =
  # Secret JWT key is parsed in constant time using nimcrypto:
  # https://github.com/cheatfate/nimcrypto/pull/44
  let secret = utils.fromHex(input)
  if secret.len == JWT_SECRET_LEN:
    ok(secret)
  else:
    err("The JWT secret should be 256 bits and hex-encoded")

proc loadJwtSecretFile*(jwtSecretFile: InputFile): Result[seq[byte], cstring] =
  try:
    let lines = readLines(string jwtSecretFile, 1)
    if lines.len > 0:
      parseJwtTokenValue(lines[0])
    else:
      err("The JWT token file should not be empty")
  except IOError:
    err("couldn't open specified JWT secret file")
  except ValueError:
    err("invalid JWT hex string")

proc checkJwtSecret*(
    rng: var HmacDrbgContext, dataDir: string, jwtSecret: Opt[InputFile]):
    Result[seq[byte], cstring] =
  # If such a parameter is given, but the file cannot be read, or does not
  # contain a hex-encoded key of 256 bits, the client should treat this as an
  # error: either abort the startup, or show error and continue without
  # exposing the authenticated port.
  if jwtSecret.isNone:
    # If such a parameter is not given, the client SHOULD generate such a
    # token, valid for the duration of the execution, and store the
    # hex-encoded secret as a jwt.hex file on the filesystem. This file can
    # then be used to provision the counterpart client.
    #
    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/authentication.md#key-distribution
    const jwtSecretFilename = "jwt.hex"
    let jwtSecretPath = dataDir / jwtSecretFilename

    let newSecret = rng.generateBytes(JWT_SECRET_LEN)
    try:
      writeFile(jwtSecretPath, newSecret.to0xHex())
    except IOError as exc:
      # Allow continuing to run, though this is effectively fatal for a merge
      # client using authentication. This keeps it lower-risk initially.
      warn "Could not write JWT secret to data directory",
        jwtSecretPath,
        err = exc.msg
    return ok(newSecret)

  loadJwtSecretFile(jwtSecret.get)
