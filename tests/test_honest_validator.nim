{.used.}

import
  unittest, stint, ./testutil,
  ../beacon_chain/spec/[datatypes, network]

suiteReport "Honest validator":
  var forkDigest: ForkDigest

  timedTest "Attestation topics":
    check:
      getAttestationTopic(forkDigest, 0) == "/eth2/00000000/committee_index0_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 9) == "/eth2/00000000/committee_index9_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 10) == "/eth2/00000000/committee_index10_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 11) == "/eth2/00000000/committee_index11_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 14) == "/eth2/00000000/committee_index14_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 22) == "/eth2/00000000/committee_index22_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 34) == "/eth2/00000000/committee_index34_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 46) == "/eth2/00000000/committee_index46_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 60) == "/eth2/00000000/committee_index60_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 63) == "/eth2/00000000/committee_index63_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 200) == "/eth2/00000000/committee_index8_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 400) == "/eth2/00000000/committee_index16_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 469) == "/eth2/00000000/committee_index21_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 550) == "/eth2/00000000/committee_index38_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 600) == "/eth2/00000000/committee_index24_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 613) == "/eth2/00000000/committee_index37_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 733) == "/eth2/00000000/committee_index29_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 775) == "/eth2/00000000/committee_index7_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 888) == "/eth2/00000000/committee_index56_beacon_attestation/ssz"
      getAttestationTopic(forkDigest, 995) == "/eth2/00000000/committee_index35_beacon_attestation/ssz"
