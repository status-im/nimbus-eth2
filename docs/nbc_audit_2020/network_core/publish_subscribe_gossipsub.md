---
title: "Publish/Subscribe protocol (gossipsub)"
code_owner: "Giovanni Petrantoni (sinkingsugar)"
round: "Audit round 4"
category: "Network Core Audit"
repositories: "nim-libp2p"
---

Seems that gossipsub might not be ready for Round 1 : libp2p/gossipsub1.1

Base spec here: [https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md)

Gossip 1.1 here: [https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)

Published paper: [https://arxiv.org/pdf/2007.02754.pdf](https://arxiv.org/pdf/2007.02754.pdf)

Gossip 1.1 is basically sitting on top of 1.0 so both specs knowledge is kind of necessary.

### Code hot paths and major importance points

Publishing:

[https://github.com/status-im/nim-libp2p/blob/d75cc6edcaf1ebcb422d3f42633f58cde6a62592/libp2p/protocols/pubsub/gossipsub.nim#L1153](https://github.com/status-im/nim-libp2p/blob/d75cc6edcaf1ebcb422d3f42633f58cde6a62592/libp2p/protocols/pubsub/gossipsub.nim#L1153)

RPC management: (within that we have validation, relevant for NBC)

[https://github.com/status-im/nim-libp2p/blob/d75cc6edcaf1ebcb422d3f42633f58cde6a62592/libp2p/protocols/pubsub/gossipsub.nim#L1024](https://github.com/status-im/nim-libp2p/blob/d75cc6edcaf1ebcb422d3f42633f58cde6a62592/libp2p/protocols/pubsub/gossipsub.nim#L1024)

Maintenance heartbeat:

[https://github.com/status-im/nim-libp2p/blob/d75cc6edcaf1ebcb422d3f42633f58cde6a62592/libp2p/protocols/pubsub/gossipsub.nim#L737](https://github.com/status-im/nim-libp2p/blob/d75cc6edcaf1ebcb422d3f42633f58cde6a62592/libp2p/protocols/pubsub/gossipsub.nim#L737)

----------------------------------------------------------------

here's a list of issues files for this workpackage:

https://github.com/status-im/nimbus-eth2/issues/1885
https://github.com/status-im/nimbus-eth2/issues/1878
https://github.com/status-im/nimbus-eth2/issues/1877
https://github.com/status-im/nimbus-eth2/issues/1876
https://github.com/status-im/nimbus-eth2/issues/1875
https://github.com/status-im/nimbus-eth2/issues/1874
https://github.com/status-im/nimbus-eth2/issues/1873
https://github.com/status-im/nimbus-eth2/issues/1871
