{.used.}

import
  unittest, stint, ./testutil,
  ../beacon_chain/spec/network

suiteReport "Honest validator":
  timedTest "Attestation topics":
    check:
      getAttestationTopic(0) == "/eth2/committee_index0_beacon_attestation/ssz"
      getAttestationTopic(9) == "/eth2/committee_index9_beacon_attestation/ssz"
      getAttestationTopic(10) == "/eth2/committee_index10_beacon_attestation/ssz"
      getAttestationTopic(11) == "/eth2/committee_index11_beacon_attestation/ssz"
      getAttestationTopic(14) == "/eth2/committee_index14_beacon_attestation/ssz"
      getAttestationTopic(22) == "/eth2/committee_index22_beacon_attestation/ssz"
      getAttestationTopic(34) == "/eth2/committee_index34_beacon_attestation/ssz"
      getAttestationTopic(46) == "/eth2/committee_index46_beacon_attestation/ssz"
      getAttestationTopic(60) == "/eth2/committee_index60_beacon_attestation/ssz"
      getAttestationTopic(63) == "/eth2/committee_index63_beacon_attestation/ssz"
      getAttestationTopic(200) == "/eth2/committee_index8_beacon_attestation/ssz"
      getAttestationTopic(400) == "/eth2/committee_index16_beacon_attestation/ssz"
      getAttestationTopic(469) == "/eth2/committee_index21_beacon_attestation/ssz"
      getAttestationTopic(550) == "/eth2/committee_index38_beacon_attestation/ssz"
      getAttestationTopic(600) == "/eth2/committee_index24_beacon_attestation/ssz"
      getAttestationTopic(613) == "/eth2/committee_index37_beacon_attestation/ssz"
      getAttestationTopic(733) == "/eth2/committee_index29_beacon_attestation/ssz"
      getAttestationTopic(775) == "/eth2/committee_index7_beacon_attestation/ssz"
      getAttestationTopic(888) == "/eth2/committee_index56_beacon_attestation/ssz"
      getAttestationTopic(995) == "/eth2/committee_index35_beacon_attestation/ssz"
