# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils, streams,
  # Status libraries
  stint, stew/bitseqs,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, digest, crypto],
  ../../beacon_chain/ssz

# Config
# ---------------------------------------------

const
  FixturesDir = currentSourcePath.rsplit(DirSep, 1)[0] / "fixtures"
  SSZDir = FixturesDir/"tests-v0.9.1"/const_preset/"phase0"/"ssz_static"
  UnitTestDir = SSZDir/"Attestation"/"ssz_lengthy"/"case_12"

type
  SSZHashTreeRoot = object
    # The test files have the values at the "root"
    # so we **must** use "root" as a field name
    root: string
    # Some have a signing_root field
    signing_root: string

# Make signing root optional
setDefaultValue(SSZHashTreeRoot, signing_root, "")

# Parsing + Test
# ---------------------------------------------

type Skip = enum
  SkipNone
  SkipHashTreeRoot
  SkipSigningRoot

proc checkSSZ(T: typedesc, dir: string, expectedHash: SSZHashTreeRoot, skip = SkipNone) =
  # Deserialize into a ref object to not fill Nim stack
  var deserialized: ref T
  new deserialized
  deserialized[] = SSZ.loadFile(dir/"serialized.ssz", T)

  echo "\n\nObject: ", T
  echo "---------------------------------------"
  echo deserialized[]

  if not(skip == SkipHashTreeRoot):
    check: expectedHash.root == "0x" & toLowerASCII($deserialized.hashTreeRoot())
  if expectedHash.signing_root != "" and not(skip == SkipSigningRoot):
    check: expectedHash.signing_root == "0x" & toLowerASCII($deserialized[].signingRoot())

proc loadExpectedHashTreeRoot(dir: string): SSZHashTreeRoot =
  var s = openFileStream(dir/"roots.yaml")
  yaml.load(s, result)
  s.close()

# Manual checks
# ---------------------------------------------

# Compile with -d:ssz_testing for consensus objects
# as they are always an Opaque Blob even if they might seem like a valid BLS signature

echo "Current preset: ", const_preset

let hash = loadExpectedHashTreeRoot(UnitTestDir)
checkSSZ(Attestation, UnitTestDir, hash)
