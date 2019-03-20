import
  unittest,
  ../beacon_chain/spec/[bitfield]

suite "BitField":
  test "roundtrips":
    var
      a = BitField.init(100)
      b = BitField.init(100)

    check:
      not a.get_bitfield_bit(0)

    a.set_bitfield_bit(1)

    check:
      not a.get_bitfield_bit(0)
      a.get_bitfield_bit(1)

    b.set_bitfield_bit(2)

    a.combine(b)

    check:
      not a.get_bitfield_bit(0)
      a.get_bitfield_bit(1)
      a.get_bitfield_bit(2)
