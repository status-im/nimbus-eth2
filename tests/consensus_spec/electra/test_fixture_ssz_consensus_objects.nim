# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Standard library
  std/[
    strutils, streams, strformat,
    macros, sets],
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/datatypes/[altair, electra],
  # Status libraries
  snappy,
  # Test utilities
  ../../testutil, ../fixtures_utils, ../os_ops

from ../../../beacon_chain/spec/datatypes/bellatrix import PowBlock
from ../../../beacon_chain/spec/datatypes/capella import
  BLSToExecutionChange, SignedBLSToExecutionChange, HistoricalSummary,
  Withdrawal
from ../../../beacon_chain/spec/datatypes/deneb import
  BlobIdentifier, BlobSidecar

# SSZ tests of consensus objects (minimal/mainnet preset specific)

# Parsing definitions
# ----------------------------------------------------------------

const
  SSZDir = SszTestsDir/const_preset/"electra"/"ssz_static"

type
  SSZHashTreeRoot = object
    # The test files have the values at the "root"
    # so we **must** use "root" as a field name
    root: string
    # Some have a signing_root field
    signing_root {.defaultVal: "".}: string

# Note this only tracks HashTreeRoot
# Checking the values against the yaml file is TODO (require more flexible Yaml parser)

proc checkSSZ(
    T: type electra.SignedBeaconBlock,
    dir: string,
    expectedHash: SSZHashTreeRoot
) {.raises: [IOError, SerializationError, UnconsumedInput].} =
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

proc checkSSZ(
    T: type,
    dir: string,
    expectedHash: SSZHashTreeRoot
) {.raises: [IOError, SerializationError, UnconsumedInput].} =
  # Deserialize into a ref object to not fill Nim stack
  let
    encoded = snappy.decode(
      readFileBytes(dir/"serialized.ssz_snappy"), MaxObjectSize)
    deserialized = newClone(sszDecodeEntireInput(encoded, T))

  check:
    expectedHash.root == "0x" & toLowerAscii($hash_tree_root(deserialized[]))
    SSZ.encode(deserialized[]) == encoded
    sszSize(deserialized[]) == encoded.len

  # TODO check the value (requires YAML loader)

proc loadExpectedHashTreeRoot(
    dir: string
): SSZHashTreeRoot {.raises: [
    Exception, IOError, OSError, YamlConstructionError, YamlParserError].} =
  let s = openFileStream(dir/"roots.yaml")
  yaml.load(s, result)
  s.close()

# Test runner
# ----------------------------------------------------------------

suite "EF - Electra - SSZ consensus objects " & preset():
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
          of "AggregateAndProof": checkSSZ(electra.AggregateAndProof, path, hash)
          of "Attestation": checkSSZ(electra.Attestation, path, hash)
          of "AttestationData": checkSSZ(AttestationData, path, hash)
          of "AttesterSlashing": checkSSZ(electra.AttesterSlashing, path, hash)
          of "BeaconBlock": checkSSZ(electra.BeaconBlock, path, hash)
          of "BeaconBlockBody": checkSSZ(electra.BeaconBlockBody, path, hash)
          of "BeaconBlockHeader": checkSSZ(BeaconBlockHeader, path, hash)
          of "BeaconState": checkSSZ(electra.BeaconState, path, hash)
          of "BlobIdentifier": checkSSZ(BlobIdentifier, path, hash)
          of "BlobSidecar": checkSSZ(BlobSidecar, path, hash)
          of "BLSToExecutionChange": checkSSZ(BLSToExecutionChange, path, hash)
          of "Checkpoint": checkSSZ(Checkpoint, path, hash)
          of "Consolidation": checkSSZ(Consolidation, path, hash)
          of "ContributionAndProof": checkSSZ(ContributionAndProof, path, hash)
          of "Deposit": checkSSZ(Deposit, path, hash)
          of "DepositData": checkSSZ(DepositData, path, hash)
          of "DepositMessage": checkSSZ(DepositMessage, path, hash)
          of "DepositReceipt": checkSSZ(DepositReceipt, path, hash)
          of "Eth1Block": checkSSZ(Eth1Block, path, hash)
          of "Eth1Data": checkSSZ(Eth1Data, path, hash)
          of "ExecutionLayerWithdrawalRequest":
            checkSSZ(ExecutionLayerWithdrawalRequest, path, hash)
          of "ExecutionPayload": checkSSZ(electra.ExecutionPayload, path, hash)
          of "ExecutionPayloadHeader":
            checkSSZ(electra.ExecutionPayloadHeader, path, hash)
          of "Fork": checkSSZ(Fork, path, hash)
          of "ForkData": checkSSZ(ForkData, path, hash)
          of "HistoricalBatch": checkSSZ(HistoricalBatch, path, hash)
          of "HistoricalSummary": checkSSZ(HistoricalSummary, path, hash)
          of "IndexedAttestation": checkSSZ(electra.IndexedAttestation, path, hash)
          of "LightClientBootstrap":
            checkSSZ(electra.LightClientBootstrap, path, hash)
          of "LightClientHeader": checkSSZ(electra.LightClientHeader, path, hash)
          of "LightClientUpdate": checkSSZ(electra.LightClientUpdate, path, hash)
          of "LightClientFinalityUpdate":
            checkSSZ(electra.LightClientFinalityUpdate, path, hash)
          of "LightClientOptimisticUpdate":
            checkSSZ(electra.LightClientOptimisticUpdate, path, hash)
          of "PendingAttestation": checkSSZ(PendingAttestation, path, hash)
          of "PendingBalanceDeposit":
            checkSSZ(PendingBalanceDeposit, path, hash)
          of "PendingConsolidation": checkSSZ(PendingConsolidation, path, hash)
          of "PendingPartialWithdrawal":
            checkSSZ(PendingPartialWithdrawal, path, hash)
          of "PowBlock": checkSSZ(PowBlock, path, hash)
          of "ProposerSlashing": checkSSZ(ProposerSlashing, path, hash)
          of "SignedAggregateAndProof":
            checkSSZ(electra.SignedAggregateAndProof, path, hash)
          of "SignedBeaconBlock":
            checkSSZ(electra.SignedBeaconBlock, path, hash)
          of "SignedBeaconBlockHeader":
            checkSSZ(SignedBeaconBlockHeader, path, hash)
          of "SignedBLSToExecutionChange":
            checkSSZ(SignedBLSToExecutionChange, path, hash)
          of "SignedContributionAndProof":
            checkSSZ(SignedContributionAndProof, path, hash)
          of "SignedConsolidation": checkSSZ(SignedConsolidation, path, hash)
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