{.used.}

import
  unittest, stint, ./testutil,
  ../beacon_chain/spec/network

suiteReport "Honest validator":
  timedTest "Attestation topics":
    check:
      getAttestationTopic(0) == "/eth2/index0_beacon_attestation/ssz"
      getAttestationTopic(9) == "/eth2/index9_beacon_attestation/ssz"
      getAttestationTopic(10) == "/eth2/index10_beacon_attestation/ssz"
      getAttestationTopic(11) == "/eth2/index11_beacon_attestation/ssz"
      getAttestationTopic(14) == "/eth2/index14_beacon_attestation/ssz"
      getAttestationTopic(22) == "/eth2/index22_beacon_attestation/ssz"
      getAttestationTopic(34) == "/eth2/index34_beacon_attestation/ssz"
      getAttestationTopic(46) == "/eth2/index46_beacon_attestation/ssz"
      getAttestationTopic(60) == "/eth2/index60_beacon_attestation/ssz"
      getAttestationTopic(63) == "/eth2/index63_beacon_attestation/ssz"
      getAttestationTopic(200) == "/eth2/index8_beacon_attestation/ssz"
      getAttestationTopic(400) == "/eth2/index16_beacon_attestation/ssz"
      getAttestationTopic(469) == "/eth2/index21_beacon_attestation/ssz"
      getAttestationTopic(550) == "/eth2/index38_beacon_attestation/ssz"
      getAttestationTopic(600) == "/eth2/index24_beacon_attestation/ssz"
      getAttestationTopic(613) == "/eth2/index37_beacon_attestation/ssz"
      getAttestationTopic(733) == "/eth2/index29_beacon_attestation/ssz"
      getAttestationTopic(775) == "/eth2/index7_beacon_attestation/ssz"
      getAttestationTopic(888) == "/eth2/index56_beacon_attestation/ssz"
      getAttestationTopic(995) == "/eth2/index35_beacon_attestation/ssz"
