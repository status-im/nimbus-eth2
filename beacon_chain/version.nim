# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## This module implements the version tagging details of all binaries included
## in the Nimbus release process (i.e. beacon_node, validator_client, etc)

import std/[os, strutils], ./buildinfo
from stew/byteutils import hexToByteArray, toHex

const
  versionMajor* = 26
  versionMinor* = 10
  versionBuild* = 2

  versionBlob* = "stateofus" # Single word - ends up in the default graffiti

  sourcePath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]
  gitRevisionBytes* = hexToByteArray[4](
    strip(generateGitRevision(sourcePath))[0..7]) # First 4 bytes of the build commit
  gitRevision* = toHex(gitRevisionBytes)[0..5]

  versionAsStr* =
    $versionMajor & "." & $versionMinor & "." & $versionBuild

  fullVersionStr* = "v" & versionAsStr & "-" & gitRevision & "-" & versionBlob

  nimbusAgentStr* = "Nimbus/" & fullVersionStr

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.7/src/engine/identification.md#clientversionv1
  clientCode* = "NB"
  clientName* = "Nimbus"
  clientVersionStr* = "v" & versionAsStr

when not defined(nimscript):
  import metrics
  declareGauge versionGauge, "Nimbus version info (as metric labels)", ["version", "commit"], name = "version"
  versionGauge.set(1, labelValues=[fullVersionStr, gitRevision])
