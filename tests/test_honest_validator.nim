{.used.}

import
  unittest, stint, ./testutil,
  ../beacon_chain/spec/network

suite "Honest validator":
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
