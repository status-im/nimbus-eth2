import byteutils, json_serialization, std_shims/support/bitops2

type
  BitField* = object
    ## A simple bit field type that follows the semantics of the spec, with
    ## regards to bit endian operations
    # TODO nim-ranges contains utilities for with bitsets - could try to
    #      recycle that, but there are open questions about bit endianess there.
    bits*: seq[byte]

func ceil_div8(v: int): int = (v + 7) div 8

func init*(T: type BitField, bits: int): BitField =
  BitField(bits: newSeq[byte](ceil_div8(bits)))

# TODO fix this for state tests..
#proc readValue*(r: var JsonReader, a: var BitField) {.inline.} =
#  a.bits = r.readValue(string).hexToSeqByte()

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.0/specs/core/0_beacon-chain.md#get_bitfield_bit
func get_bitfield_bit*(bitfield: BitField, i: int): bool =
  # Extract the bit in ``bitfield`` at position ``i``.
  doAssert 0 <= i div 8, "i: " & $i & " i div 8: " & $(i div 8)
  doAssert i div 8 < bitfield.bits.len, "i: " & $i & " i div 8: " & $(i div 8)
  ((bitfield.bits[i div 8] shr (i mod 8)) mod 2) > 0'u8

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.0/specs/core/0_beacon-chain.md#verify_bitfield
func verify_bitfield*(bitfield: BitField, committee_size: int): bool =
  # Verify ``bitfield`` against the ``committee_size``.
  if len(bitfield.bits) != (committee_size + 7) div 8:
    return false

  # Check `bitfield` is padded with zero bits only
  for i in committee_size ..< (len(bitfield.bits) * 8):
    if get_bitfield_bit(bitfield, i):
      return false

  true

# TODO spec candidatidates below, though they're used only indirectly there..
func set_bitfield_bit*(bitfield: var BitField, i: int) =
  bitfield.bits[i div 8] = bitfield.bits[i div 8] or 1'u8 shl (i mod 8)

func combine*(tgt: var BitField, src: BitField) =
  for i in 0 ..< tgt.bits.len:
    tgt.bits[i] = tgt.bits[i] or src.bits[i]

func overlaps*(a, b: BitField): bool =
  for i in 0..<a.bits.len:
    if (a.bits[i] and b.bits[i]) > 0'u8:
      return true

func countOnes*(a: BitField): int {.inline.} =
  for v in a.bits: result += countOnes(v)

func len*(a: BitField): int {.inline.} =
  countOnes(a)

func isSubsetOf*(a, b: Bitfield): bool =
  for i in 0 ..< (len(a.bits) * 8):
    if get_bitfield_bit(a, i) and not get_bitfield_bit(b, i):
      return false
  true
