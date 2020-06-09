{.used.}

import
  unittest, ./testutil,
  ../beacon_chain/spec/[datatypes, network]

suiteReport "Honest validator":
  var forkDigest: ForkDigest

  timedTest "General pubsub topics:":
    check:
      getBeaconBlocksTopic(forkDigest) == "/eth2/00000000/beacon_block/ssz"
      getVoluntaryExitsTopic(forkDigest) == "/eth2/00000000/voluntary_exit/ssz"
      getProposerSlashingsTopic(forkDigest) == "/eth2/00000000/proposer_slashing/ssz"
      getAttesterSlashingsTopic(forkDigest) == "/eth2/00000000/attester_slashing/ssz"
      when ETH2_SPEC == "v0.11.3":
        getInteropAttestationTopic(forkDigest) == "/eth2/00000000/beacon_attestation/ssz"
      else:
        true
      getAggregateAndProofsTopic(forkDigest) == "/eth2/00000000/beacon_aggregate_and_proof/ssz"

  timedTest "Mainnet attestation topics":
    check:
      getMainnetAttestationTopic(forkDigest, 0) ==
        "/eth2/00000000/committee_index0_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 9) ==
        "/eth2/00000000/committee_index9_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 10) ==
        "/eth2/00000000/committee_index10_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 11) ==
        "/eth2/00000000/committee_index11_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 14) ==
        "/eth2/00000000/committee_index14_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 22) ==
        "/eth2/00000000/committee_index22_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 34) ==
        "/eth2/00000000/committee_index34_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 46) ==
        "/eth2/00000000/committee_index46_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 60) ==
        "/eth2/00000000/committee_index60_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 63) ==
        "/eth2/00000000/committee_index63_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 200) ==
        "/eth2/00000000/committee_index8_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 400) ==
        "/eth2/00000000/committee_index16_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 469) ==
        "/eth2/00000000/committee_index21_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 550) ==
        "/eth2/00000000/committee_index38_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 600) ==
        "/eth2/00000000/committee_index24_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 613) ==
        "/eth2/00000000/committee_index37_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 733) ==
        "/eth2/00000000/committee_index29_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 775) ==
        "/eth2/00000000/committee_index7_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 888) ==
        "/eth2/00000000/committee_index56_beacon_attestation/ssz"
      getMainnetAttestationTopic(forkDigest, 995) ==
        "/eth2/00000000/committee_index35_beacon_attestation/ssz"
