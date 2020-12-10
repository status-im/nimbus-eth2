{.used.}

import
  unittest, ./testutil,
  ../beacon_chain/spec/[crypto, datatypes, network],
  ../beacon_chain/attestation_aggregation

suiteReport "Honest validator":
  var forkDigest: ForkDigest

  timedTest "General pubsub topics":
    check:
      getBeaconBlocksTopic(forkDigest) == "/eth2/00000000/beacon_block/ssz"
      getVoluntaryExitsTopic(forkDigest) == "/eth2/00000000/voluntary_exit/ssz"
      getProposerSlashingsTopic(forkDigest) == "/eth2/00000000/proposer_slashing/ssz"
      getAttesterSlashingsTopic(forkDigest) == "/eth2/00000000/attester_slashing/ssz"
      getAggregateAndProofsTopic(forkDigest) == "/eth2/00000000/beacon_aggregate_and_proof/ssz"

  timedTest "Mainnet attestation topics":
    check:
      getAttestationTopic(forkDigest, 0) ==
        "/eth2/00000000/beacon_attestation_0/ssz"
      getAttestationTopic(forkDigest, 5) ==
        "/eth2/00000000/beacon_attestation_5/ssz"
      getAttestationTopic(forkDigest, 7) ==
        "/eth2/00000000/beacon_attestation_7/ssz"
      getAttestationTopic(forkDigest, 9) ==
        "/eth2/00000000/beacon_attestation_9/ssz"
      getAttestationTopic(forkDigest, 13) ==
        "/eth2/00000000/beacon_attestation_13/ssz"
      getAttestationTopic(forkDigest, 19) ==
        "/eth2/00000000/beacon_attestation_19/ssz"
      getAttestationTopic(forkDigest, 20) ==
        "/eth2/00000000/beacon_attestation_20/ssz"
      getAttestationTopic(forkDigest, 22) ==
        "/eth2/00000000/beacon_attestation_22/ssz"
      getAttestationTopic(forkDigest, 25) ==
        "/eth2/00000000/beacon_attestation_25/ssz"
      getAttestationTopic(forkDigest, 27) ==
        "/eth2/00000000/beacon_attestation_27/ssz"
      getAttestationTopic(forkDigest, 31) ==
        "/eth2/00000000/beacon_attestation_31/ssz"
      getAttestationTopic(forkDigest, 39) ==
        "/eth2/00000000/beacon_attestation_39/ssz"
      getAttestationTopic(forkDigest, 45) ==
        "/eth2/00000000/beacon_attestation_45/ssz"
      getAttestationTopic(forkDigest, 47) ==
        "/eth2/00000000/beacon_attestation_47/ssz"
      getAttestationTopic(forkDigest, 48) ==
        "/eth2/00000000/beacon_attestation_48/ssz"
      getAttestationTopic(forkDigest, 50) ==
        "/eth2/00000000/beacon_attestation_50/ssz"
      getAttestationTopic(forkDigest, 53) ==
        "/eth2/00000000/beacon_attestation_53/ssz"
      getAttestationTopic(forkDigest, 54) ==
        "/eth2/00000000/beacon_attestation_54/ssz"
      getAttestationTopic(forkDigest, 62) ==
        "/eth2/00000000/beacon_attestation_62/ssz"
      getAttestationTopic(forkDigest, 63) ==
        "/eth2/00000000/beacon_attestation_63/ssz"

  timedTest "is_aggregator":
    check:
      not is_aggregator(146, ValidatorSig.fromHex(
        "aa176502f0a5e954e4c6b452d0e11a03513c19b6d189f125f07b6c5c120df011c31da4c4a9c4a52a5a48fcba5b14d7b316b986a146187966d2341388bbf1f86c42e90553ba009ba10edc6b5544a6e945ce6d2419197f66ab2b9df2b0a0c89987")[])
      is_aggregator(147, ValidatorSig.fromHex(
        "91a49ae4edfb4b1c9f7856f49c9b0f6d2278b0f714edd6654bf91678d08c0554b8c8bc375f88ffc227f679bf14287dd616e6d1df264599e56516a3f6ab4d91365cc6a40a7e72edeff37c456d4b2b80fa76283911471fe1e292bf64f54cafd55f")[])
