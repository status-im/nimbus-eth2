# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  strutils, streams, strformat,
  macros, sets,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/datatypes/[altair, deneb],
  # Status libraries
  snappy,
  # Test utilities
  ../../testutil, ../fixtures_utils, ../os_ops

from ../../../beacon_chain/spec/datatypes/bellatrix import PowBlock
from ../../../beacon_chain/spec/datatypes/capella import
  BLSToExecutionChange, SignedBLSToExecutionChange, HistoricalSummary,
  Withdrawal

# SSZ tests of consensus objects (minimal/mainnet preset specific)

# Parsing definitions
# ----------------------------------------------------------------

const
  SSZDir = SszTestsDir/const_preset/"deneb"/"ssz_static"

type
  SSZHashTreeRoot = object
    # The test files have the values at the "root"
    # so we **must** use "root" as a field name
    root: string
    # Some have a signing_root field
    signing_root {.defaultVal: "".}: string

# Note this only tracks HashTreeRoot
# Checking the values against the yaml file is TODO (require more flexible Yaml parser)

proc checkSSZ(T: type deneb.SignedBeaconBlock, dir: string, expectedHash: SSZHashTreeRoot) =
   # Deserialize into a ref object to not fill Nim stack
   let encoded = snappy.decode(
     readFileBytes(dir/"serialized.ssz_snappy"), MaxObjectSize)
   let deserialized = newClone(sszDecodeEntireInput(encoded, T))

   # SignedBeaconBlocks usually not hashed because they're identified by
   # htr(BeaconBlock), so do it manually
   check: expectedHash.root == "0x" & toLowerAscii($hash_tree_root(
     [hash_tree_root(deserialized.message),
     hash_tree_root(deserialized.signature)]))

   check deserialized.root == hash_tree_root(deserialized.message)
   check SSZ.encode(deserialized[]) == encoded
   check sszSize(deserialized[]) == encoded.len

   # TODO check the value (requires YAML loader)

proc checkSSZ(T: type, dir: string, expectedHash: SSZHashTreeRoot) =
  # Deserialize into a ref object to not fill Nim stack
  let encoded = snappy.decode(
    readFileBytes(dir/"serialized.ssz_snappy"), MaxObjectSize)
  let deserialized = newClone(sszDecodeEntireInput(encoded, T))

  check: expectedHash.root == "0x" & toLowerAscii($hash_tree_root(deserialized[]))

  check SSZ.encode(deserialized[]) == encoded
  check sszSize(deserialized[]) == encoded.len

  # TODO check the value (requires YAML loader)

proc loadExpectedHashTreeRoot(dir: string): SSZHashTreeRoot =
  let s = openFileStream(dir/"roots.yaml")
  yaml.load(s, result)
  s.close()

# Test runner
# ----------------------------------------------------------------

suite "EF - Deneb - SSZ consensus objects " & preset():
  doAssert dirExists(SSZDir), "You need to run the \"download_test_vectors.sh\" script to retrieve the consensus spec test vectors."
  for pathKind, sszType in walkDir(SSZDir, relative = true, checkDir = true):
    doAssert pathKind == pcDir

    test &"  Testing    {sszType}":
      let path = SSZDir/sszType
      for pathKind, sszTestKind in walkDir(
          path, relative = true, checkDir = true):
        doAssert pathKind == pcDir
        let path = SSZDir/sszType/sszTestKind
        for pathKind, sszTestCase in walkDir(
            path, relative = true, checkDir = true):
          let path = SSZDir/sszType/sszTestKind/sszTestCase
          let hash = loadExpectedHashTreeRoot(path)

          case sszType:
          of "AggregateAndProof": checkSSZ(AggregateAndProof, path, hash)
          of "Attestation": checkSSZ(Attestation, path, hash)
          of "AttestationData": checkSSZ(AttestationData, path, hash)
          of "AttesterSlashing": checkSSZ(AttesterSlashing, path, hash)
          of "BeaconBlock": checkSSZ(deneb.BeaconBlock, path, hash)
          of "BeaconBlockBody": checkSSZ(deneb.BeaconBlockBody, path, hash)
          of "BeaconBlockHeader": checkSSZ(BeaconBlockHeader, path, hash)
          of "BeaconState": checkSSZ(deneb.BeaconState, path, hash)
          of "BlobIdentifier": checkSSZ(BlobIdentifier, path, hash)
          of "BlobSidecar": checkSSZ(BlobSidecar, path, hash)
          of "BLSToExecutionChange": checkSSZ(BLSToExecutionChange, path, hash)
          of "Checkpoint": checkSSZ(Checkpoint, path, hash)
          of "ContributionAndProof": checkSSZ(ContributionAndProof, path, hash)
          of "Deposit": checkSSZ(Deposit, path, hash)
          of "DepositData": checkSSZ(DepositData, path, hash)
          of "DepositMessage": checkSSZ(DepositMessage, path, hash)
          of "Eth1Block": checkSSZ(Eth1Block, path, hash)
          of "Eth1Data": checkSSZ(Eth1Data, path, hash)
          of "ExecutionPayload": checkSSZ(ExecutionPayload, path, hash)
          of "ExecutionPayloadHeader":
            checkSSZ(ExecutionPayloadHeader, path, hash)
          of "Fork": checkSSZ(Fork, path, hash)
          of "ForkData": checkSSZ(ForkData, path, hash)
          of "HistoricalBatch": checkSSZ(HistoricalBatch, path, hash)
          of "HistoricalSummary": checkSSZ(HistoricalSummary, path, hash)
          of "IndexedAttestation": checkSSZ(IndexedAttestation, path, hash)
          of "LightClientBootstrap":
            checkSSZ(deneb.LightClientBootstrap, path, hash)
          of "LightClientHeader": checkSSZ(deneb.LightClientHeader, path, hash)
          of "LightClientUpdate": checkSSZ(deneb.LightClientUpdate, path, hash)
          of "LightClientFinalityUpdate":
            checkSSZ(deneb.LightClientFinalityUpdate, path, hash)
          of "LightClientOptimisticUpdate":
            checkSSZ(deneb.LightClientOptimisticUpdate, path, hash)
          of "PendingAttestation": checkSSZ(PendingAttestation, path, hash)
          of "PowBlock": checkSSZ(PowBlock, path, hash)
          of "ProposerSlashing": checkSSZ(ProposerSlashing, path, hash)
          of "SignedAggregateAndProof":
            checkSSZ(SignedAggregateAndProof, path, hash)
          of "SignedBeaconBlock":
            checkSSZ(deneb.SignedBeaconBlock, path, hash)
          of "SignedBeaconBlockHeader":
            checkSSZ(SignedBeaconBlockHeader, path, hash)
          of "SignedBLSToExecutionChange":
            checkSSZ(SignedBLSToExecutionChange, path, hash)
          of "SignedContributionAndProof":
            checkSSZ(SignedContributionAndProof, path, hash)
          of "SignedVoluntaryExit": checkSSZ(SignedVoluntaryExit, path, hash)
          of "SigningData": checkSSZ(SigningData, path, hash)
          of "SyncAggregate": checkSSZ(SyncAggregate, path, hash)
          of "SyncAggregatorSelectionData":
            checkSSZ(SyncAggregatorSelectionData, path, hash)
          of "SyncCommittee": checkSSZ(SyncCommittee, path, hash)
          of "SyncCommitteeContribution":
            checkSSZ(SyncCommitteeContribution, path, hash)
          of "SyncCommitteeMessage": checkSSZ(SyncCommitteeMessage, path, hash)
          of "Withdrawal": checkSSZ(Withdrawal, path, hash)
          of "Validator": checkSSZ(Validator, path, hash)
          of "VoluntaryExit": checkSSZ(VoluntaryExit, path, hash)
          else:
            raise newException(ValueError, "Unsupported test: " & sszType)
