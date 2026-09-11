# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/gloas/partial-columns/p2p-interface.md

import
  unittest2,
  kzg4844/kzg_abi,
  ssz_serialization/bitseqs,
  libp2p/protocols/pubsub/rpc/messages,
  ../beacon_chain/spec/[eth2_ssz_serialization, forks, network],
  ../beacon_chain/networking/partial_columns

const testGroupId = gloas.PartialDataColumnGroupID(slot: Slot(3))

func bits(n: int, indices: varargs[int]): BitSeq =
  result = BitSeq.init(n)
  for i in indices:
    result.setBit(i)

func cell(i: int): KzgCell =
  result.bytes[0] = byte(i + 1)

func proof(i: int): KzgProof =
  result.bytes[0] = byte(i + 1)

func metadata(available, requests: BitSeq): seq[byte] =
  SSZ.encode(gloas.PartialDataColumnPartsMetadata(
    available: available, requests: requests))

func sampleMessage(): PartialColumnMessage =
  ## Holds the cells of blobs 0 and 2 out of 3.
  PartialColumnMessage.init(
    testGroupId, bits(3, 0, 2), [cell(0), cell(1), cell(2)],
    [proof(0), proof(1), proof(2)])

suite "Partial column messages":
  test "Group id and parts metadata":
    let pm = sampleMessage()
    check:
      pm.groupId() == encodePartialDataColumnGroupId(testGroupId)
      pm.partsMetadata() == metadata(bits(3, 0, 2), bits(3, 1))

  test "Materialize only cells the peer requests and lacks":
    let
      data = sampleMessage().materializeParts(
        metadata(bits(3, 0), bits(3, 0, 1, 2))).expect("valid metadata")
      sidecar = decodePartialDataColumnSidecar(data).expect("valid sidecar")
    check:
      sidecar.cells_present_bitmap[Natural(2)]
      not sidecar.cells_present_bitmap[Natural(0)]
      not sidecar.cells_present_bitmap[Natural(1)]
      sidecar.partial_column == @[cell(2)]
      sidecar.kzg_proofs.len == 1
      sidecar.kzg_proofs[0] == proof(2)

  test "Empty metadata materializes every available cell":
    let sidecar = decodePartialDataColumnSidecar(
      sampleMessage().materializeParts(@[]).expect("valid metadata")).expect(
        "valid sidecar")
    check sidecar.partial_column == @[cell(0), cell(2)]

  test "Nothing requested yields no data":
    check sampleMessage().materializeParts(
      metadata(bits(3), bits(3, 1))).expect("valid metadata").len == 0

  test "Mismatched bitlist length is an error":
    check sampleMessage().materializeParts(
      metadata(bits(2), bits(2, 0))).isErr

  test "Union of parts metadata":
    check:
      unionPartsMetadata(
          metadata(bits(3, 0), bits(3, 1)),
          metadata(bits(3, 2), bits(3, 0))).expect("valid metadata") ==
        metadata(bits(3, 0, 2), bits(3, 0, 1))
      unionPartsMetadata(
        metadata(bits(3), bits(3)), metadata(bits(2), bits(2))).isErr

  test "Partial RPC validation":
    let encoded = encodePartialDataColumnGroupId(testGroupId)
    check:
      validatePartialRPC(
        PartialMessageExtensionRPC(groupID: Opt.some(encoded))).isOk
      validatePartialRPC(
        PartialMessageExtensionRPC(groupID: Opt.some(@[1'u8]))).isErr
      validatePartialRPC(PartialMessageExtensionRPC(
        groupID: Opt.some(encoded),
        partsMetadata: Opt.some(@[0xff'u8]))).isErr
