import ../beacon_chain/spec/datatypes/phase0

import typetraits, strformat, strutils

proc print(t: auto, n: string, indent: int) =
  echo fmt"{sizeof(t):>8}  {spaces(indent)}{n}: {typeof(t).name}"

  when t is object | tuple:
    for n, p in t.fieldPairs:
      print(p, n, indent + 1)

print((ref BeaconState)()[], "state", 0)

echo ""

print(SignedBeaconBlock(), "block", 0)

echo ""

print(Validator(), "validator", 0)

echo ""

print(Attestation(), "attestation", 0)
