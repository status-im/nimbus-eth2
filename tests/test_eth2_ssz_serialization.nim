# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/strutils,
  unittest2,
  ../beacon_chain/spec/datatypes/[phase0, altair, bellatrix, deneb],
  ../beacon_chain/spec/eth2_ssz_serialization,
  ./consensus_spec/os_ops

static:
  doAssert isFixedSize(Slot) == true

type
  Specific = object
    f1: Slot
    f2: Epoch

  Primitive = object # Same as above, but using primitive fields
    f1: uint64
    f2: uint64

suite "Specific field types":
  test "roundtrip":
    let encoded = SSZ.encode(Specific(f1: Slot(1), f2: Epoch(2)))
    check SSZ.decode(encoded, Primitive) == Primitive(f1: 1, f2: 2)

  test "root update":
    template testit(T: type) =
      var t: T
      t.root = hash_tree_root(t.message)
      let encoded = SSZ.encode(t)
      let decoded = SSZ.decode(encoded, T)
      check:
        t.message == decoded.message
        t.root == decoded.root

      t = default(type t)
      readSszBytes(encoded, t, false)
      check:
        t.root.isZero

    testit(phase0.SignedBeaconBlock)
    testit(phase0.TrustedSignedBeaconBlock)
    testit(altair.SignedBeaconBlock)
    testit(altair.TrustedSignedBeaconBlock)

suite "Size bounds":
  test "SignedBeaconBlockDeneb":
    # https://gist.github.com/tbenr/a0ae19fe7496106886ec1f3cc097c208
    template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
    let expected = os_ops.readFile(
      sourceDir/"test_files"/"SszLengthBounds_SignedBeaconBlockDeneb.txt")

    var
      res = ""
      loc = @["SignedBeaconBlockDeneb"]
    func record(T: typedesc) =
      when T is SomeSig|ValidatorPubKey:
        res.add loc.join(".") & "[" & $T.blob.len & "]: SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        loc[^1].add "[element]"
        byte.record()
      elif T is ExecutionAddress|BloomLogs:
        res.add loc.join(".") & "[" & $T.data.len & "]: SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        loc[^1].add "[element]"
        byte.record()
      elif T is KzgCommitment:
        res.add loc.join(".") & "[" & $T.bytes.len & "]: SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        loc[^1].add "[element]"
        byte.record()
      elif T is array|HashArray:
        res.add loc.join(".") & "[" & $T.len & "]: SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        loc[^1].add "[element]"
        ElemType(T).record()
      elif T is List|HashList:
        res.add loc.join(".") & "(" & $T.maxLen & "): SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        loc[^1].add "(element)"
        ElemType(T).record()
      elif T is BitArray:
        res.add loc.join(".") & "[" & $T.bits & "]: SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        res.add loc.join(".") & "[element]: SszLengthBounds" &
          "{min=0(+1 bits), max=0(+1 bits)}\n"
      elif T is BitList:
        res.add loc.join(".") & "(" & $T.maxLen & "): SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        res.add loc.join(".") & "(element): SszLengthBounds" &
          "{min=0(+1 bits), max=0(+1 bits)}\n"
      else:
        res.add loc.join(".") & ": SszLengthBounds" &
          "{min=" & $T.minSize & ", max=" & $T.maxSize & "}\n"
        when T is object and T isnot Eth2Digest|UInt256:
          T.enumAllSerializedFields():
            loc.add fieldName
            record(FieldType)
            discard loc.pop()
    record deneb.SignedBeaconBlock
    check res.splitLines() == expected.splitLines()
