import
  unittest, stint, blscurve,
  ../beacon_chain/interop

# Interop test yaml, found here:
# https://github.com/ethereum/eth2.0-pm/blob/a0b9d22fad424574b1307828f867b30237758468/interop/mocked_start/keygen_10_validators.yaml

const privateKeys = [
  "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866",
  "0x51d0b65185db6989ab0b560d6deed19c7ead0e24b9b6372cbecb1f26bdfad000",
  "0x315ed405fafe339603932eebe8dbfd650ce5dafa561f6928664c75db85f97857",
  "0x25b1166a43c109cb330af8945d364722757c65ed2bfed5444b5a2f057f82d391",
  "0x3f5615898238c4c4f906b507ee917e9ea1bb69b93f1dbd11a34d229c3b06784b",
  "0x055794614bc85ed5436c1f5cab586aab6ca84835788621091f4f3b813761e7a8",
  "0x1023c68852075965e0f7352dee3f76a84a83e7582c181c10179936c6d6348893",
  "0x3a941600dc41e5d20e818473b817a28507c23cdfdb4b659c15461ee5c71e41f5",
  "0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06",
  "0x2b3b88a041168a1c4cd04bdd8de7964fd35238f95442dc678514f9dadb81ec34",
]

suite "Interop":
  test "Mocked start private key":
    for i, k in privateKeys:
      let
        key = makeInteropPrivKey(i)
        v = k.parse(UInt256, 16)

      check:
        # getBytes is bigendian and returns full 48 bytes of key..
        Uint256.fromBytesBE(key.getBytes()[48-32..<48]) == v
