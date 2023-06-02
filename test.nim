template foo(): auto =
  {.noSideEffect.}:
    newSeq[byte](1)

type V = object
  v: seq[byte]

proc bar(): V =
  V(v: foo())

echo bar().v
