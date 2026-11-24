# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[json, strutils],
  unittest2,
  stew/byteutils,
  ../beacon_chain/spec/eth2_apis/eth2_rest_serialization

func testPubkey(fill: byte): XMSSPubkey =
  var res: XMSSPubkey
  for i in 0 ..< res.blob.len:
    res.blob[i] = fill
  res

func testSignature(fill: byte): XMSSSignature =
  var res: XMSSSignature
  for i in 0 ..< res.blob.len:
    res.blob[i] = fill + byte(i mod 7)
  res

func testVrfProof(): VRFProof =
  var res: VRFProof
  for i in 0 ..< res.len:
    for j in 0 ..< 32:
      res[i].data[j] = byte((i * 32 + j) mod 251)
  res

func testAttestationData(): AttestationData =
  AttestationData(
    slot: 9.Slot, index: 1,
    beacon_block_root: Eth2Digest.fromHex("0x" & "11".repeat(32)),
    source: Checkpoint(epoch: 0.Epoch),
    target: Checkpoint(
      epoch: 1.Epoch, root: Eth2Digest.fromHex("0x" & "22".repeat(32))))

template jsonRoundTrip(value: auto): bool =
  RestJson.decode(RestJson.encode(value), typeof(value)) == value

const
  jsonType = "application/json"
  sszType = "application/octet-stream"

suite "PQ REST encoding and decoding":
  test "ValidatorIdent of an XMSS public key":
    let
      pubkey = testPubkey(0xab)
      hex = "0x" & "ab".repeat(32)
      ident = ValidatorIdent.parse(hex)
    check:
      ident.isOk()
      ident.get().kind == ValidatorQueryKind.XmssKey
      ident.get().xmssKey == pubkey
      ValidatorIdent.init(pubkey).xmssKey == pubkey
      encodeString(ident.get()).get() == hex
      decodeString(ValidatorIdent, hex).get().xmssKey == pubkey
      RestJson.encode(ident.get()) == "\"" & hex & "\""
      RestJson.decode("\"" & hex & "\"", ValidatorIdent).xmssKey == pubkey

      # Indices and BLS keys are what they were
      ValidatorIdent.parse("17").get().kind == ValidatorQueryKind.Index
      ValidatorIdent.parse(
        "0x" & ValidatorPubKey.default.toHex()).get().kind ==
          ValidatorQueryKind.Key
      ValidatorIdent.parse("0x" & "ab".repeat(31)).isErr()
      ValidatorIdent.parse("0x" & "zz".repeat(32)).isErr()

  test "PQ validator":
    let validator = RestPqValidator.init(
      5.ValidatorIndex, 32_000_000_000.Gwei, "active_ongoing",
      PqValidator(
        pubkey: testPubkey(1),
        vrf_root: Eth2Digest.fromHex("0x" & "33".repeat(32)),
        effective_balance: 32_000_000_000.Gwei,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH))
    check jsonRoundTrip(validator)
    let node =
      try:
        parseJson(RestJson.encode(validator))
      except CatchableError:
        raiseAssert "valid JSON"
    check:
      node["index"].getStr() == "5"
      node["balance"].getStr() == "32000000000"
      node["status"].getStr() == "active_ongoing"
      node["validator"]["pubkey"].getStr() == "0x" & "01".repeat(32)
      node["validator"]["vrf_root"].getStr() == "0x" & "33".repeat(32)
      node["validator"]["exit_epoch"].getStr() == "18446744073709551615"
      jsonRoundTrip(RestPqValidatorIdentity(
        index: 5.ValidatorIndex, pubkey: testPubkey(1),
        activation_epoch: 2.Epoch))

  test "PQ duties":
    let
      attester = RestPqAttesterDuty(
        pubkey: testPubkey(2), validator_index: 7.ValidatorIndex,
        committee_index: 1.CommitteeIndex, committee_length: 4,
        committees_at_slot: 2, validator_committee_index: 3, slot: 9.Slot,
        is_aggregator: true)
      proposer = RestPqProposerDuty(
        pubkey: testPubkey(3), validator_index: 8.ValidatorIndex,
        slot: 10.Slot)
      ptc = RestPqPtcDuty(
        pubkey: testPubkey(4), validator_index: 9.ValidatorIndex,
        slot: 11.Slot)
    check:
      jsonRoundTrip(attester)
      jsonRoundTrip(proposer)
      jsonRoundTrip(ptc)
      RestJson.encode(attester) ==
        "{\"pubkey\":\"0x" & "02".repeat(32) & "\",\"validator_index\":\"7\"," &
        "\"committee_index\":\"1\",\"committee_length\":\"4\"," &
        "\"committees_at_slot\":\"2\",\"validator_committee_index\":\"3\"," &
        "\"slot\":\"9\",\"is_aggregator\":true}"
      RestJson.encode(proposer) ==
        "{\"pubkey\":\"0x" & "03".repeat(32) &
        "\",\"validator_index\":\"8\",\"slot\":\"10\"}"

    # As a validator client reads them
    let
      body = "{\"dependent_root\":\"0x" & "44".repeat(32) &
        "\",\"execution_optimistic\":false,\"data\":[" &
        RestJson.encode(attester) & "]}"
      decoded = decodeBytes(
        GetPqAttesterDutiesResponse, body.toBytes(),
        Opt.some(getContentType(jsonType).get()))
    check:
      decoded.isOk()
      decoded.get().data == @[attester]

  test "VRF proof as RANDAO reveal":
    let
      proof = testVrfProof()
      encoded = encodeString(proof).get()
    check:
      encoded.len == 2 + 2 * 1024
      encoded == to0xHex(SSZ.encode(proof))
      decodeString(VRFProof, encoded).get() == proof
      decodeString(VRFProof, encoded[2 .. ^1]).isErr()
      decodeString(VRFProof, encoded[0 ..< encoded.len - 2]).isErr()
      decodeString(VRFProof, "0x" & "zz".repeat(1024)).isErr()
      # A BLS signature is not one
      decodeString(VRFProof, "0x" & "00".repeat(96)).isErr()

  test "Single attestations":
    let attestations = @[PqSingleAttestation(
      committee_index: 1, attester_index: 7, data: testAttestationData(),
      signature: testSignature(5))]
    check jsonRoundTrip(attestations)
    let
      encoded = encodeBytes(attestations, jsonType).get()
      node =
        try:
          parseJson(string.fromBytes(encoded))
        except CatchableError:
          raiseAssert "valid JSON"
    check:
      node[0]["committee_index"].getStr() == "1"
      node[0]["attester_index"].getStr() == "7"
      node[0]["data"]["slot"].getStr() == "9"
      node[0]["signature"].getStr().len == 2 + 2 * XMSS_SIGNATURE_SIZE

  test "Aggregate and proof":
    var attestation = pq.Attestation(
      aggregation_bits: gloas.AggregationBits.init(4),
      data: testAttestationData())
    attestation.aggregation_bits[1] = true
    attestation.committee_bits[1] = true
    let
      aggregate = RestPqAggregate(
        aggregate: attestation,
        proof: AttestationProof.init(@[byte 1, 2, 3, 4]))
      signed = @[pq.SignedAggregateAndProof(
        message: pq.AggregateAndProof(
          aggregator_index: 7, aggregate: attestation,
          proof: aggregate.proof),
        signature: testSignature(9))]
    check:
      jsonRoundTrip(aggregate)
      SSZ.decode(SSZ.encode(aggregate), RestPqAggregate) == aggregate
      jsonRoundTrip(signed)
      RestJson.decode(
        string.fromBytes(encodeBytes(signed, jsonType).get()),
        seq[pq.SignedAggregateAndProof]) == signed

    # As a validator client reads the aggregate
    let
      body = "{\"version\":\"pq\",\"data\":" & RestJson.encode(aggregate) & "}"
      decoded = decodeBytes(
        GetPqAggregateResponse, body.toBytes(),
        Opt.some(getContentType(jsonType).get()))
      node =
        try:
          parseJson(body)
        except CatchableError:
          raiseAssert "valid JSON"
    check:
      decoded.isOk()
      decoded.get().data == aggregate
      node["data"]["proof"].getStr() == "0x01020304"
      node["data"]["aggregate"].hasKey("aggregation_bits")
      node["data"]["aggregate"].hasKey("committee_bits")
      not node["data"]["aggregate"].hasKey("signature")

  test "Produced block":
    var contents = PqProducedBlockContents()
    contents.`block`.slot = 9.Slot
    contents.`block`.proposer_index = 7
    contents.`block`.body.randao_reveal = testVrfProof()
    contents.`block`.body.proof = AttestationProof.init(@[byte 5, 6])
    contents.execution_payload_envelope.beacon_block_root =
      hash_tree_root(contents.`block`)
    contents.execution_payload_envelope.payload.slot_number = 9.Slot
    check:
      jsonRoundTrip(contents)
      SSZ.decode(SSZ.encode(contents), PqProducedBlockContents) == contents

    let
      response = ProduceBlockResponseV4(
        data: ForkedProducedBlock(
          includePayload: true,
          contents: ForkedProducedBlockContents.init(contents)),
        consensusBlockValue: Opt.some(0.u256),
        executionPayloadValue: Opt.some(12345.u256))
      encoded = RestJson.encode(response)
      node =
        try:
          parseJson(encoded)
        except CatchableError:
          raiseAssert "valid JSON"
    check:
      node["version"].getStr() == "pq"
      node["consensus_block_value"].getStr() == "0"
      node["execution_payload_value"].getStr() == "12345"
      node["execution_payload_included"].getBool()
      node["data"]["block"]["slot"].getStr() == "9"
      node["data"]["block"]["body"]["randao_reveal"].len == 32
      node["data"]["block"]["body"]["proof"].getStr() == "0x0506"
      node["data"]["execution_payload_envelope"]["builder_index"].getStr() ==
        "0"
      node["data"]["kzg_proofs"].len == 0
      node["data"]["blobs"].len == 0

    let fromJson = decodeBytes(
      ProduceBlockResponseV4, encoded.toBytes(),
      Opt.some(getContentType(jsonType).get()), "pq", "true", "12345", "0", "")
    check:
      fromJson.isOk()
      fromJson.get().data.includePayload
      fromJson.get().data.contents.kind == ConsensusFork.Pq
      fromJson.get().data.contents.pqData == contents
      fromJson.get().executionPayloadValue == Opt.some(12345.u256)

    let fromSsz = decodeBytes(
      ProduceBlockResponseV4, SSZ.encode(contents),
      Opt.some(getContentType(sszType).get()), "pq", "true", "12345", "0", "")
    check:
      fromSsz.isOk()
      fromSsz.get().data.includePayload
      fromSsz.get().data.contents.pqData == contents

    let blockOnly = decodeBytes(
      ProduceBlockResponseV4, SSZ.encode(contents.`block`),
      Opt.some(getContentType(sszType).get()), "pq", "false", "1", "0", "")
    check:
      blockOnly.isOk()
      not blockOnly.get().data.includePayload
      blockOnly.get().data.blck.kind == ConsensusFork.Pq
      blockOnly.get().data.blck.pqData == contents.`block`

  test "Signed block":
    var blck: pq.SignedBeaconBlock
    blck.message.slot = 9.Slot
    blck.message.body.randao_reveal = testVrfProof()
    blck.signature = testSignature(3)
    blck.root = hash_tree_root(blck.message)
    for contentType in [jsonType, sszType]:
      let
        body = ContentBody(
          contentType: getContentType(contentType).get(),
          data: encodeBytes(blck, contentType).get())
        decoded = decodeBody(RestPublishedSignedBlockContents, body, "pq")
      check:
        decoded.isOk()
        decoded.get().kind == ConsensusFork.Pq
        decoded.get().pqData.message == blck.message
        decoded.get().pqData.signature == blck.signature
        decoded.get().pqData.root == blck.root

  test "Envelope with and without blob data":
    var contents: PqSignedExecutionPayloadEnvelopeContents
    template envelope: untyped = contents.signed_execution_payload_envelope
    envelope.message.payload.slot_number = 9.Slot
    envelope.message.beacon_block_root =
      Eth2Digest.fromHex("0x" & "55".repeat(32))
    envelope.signature = testSignature(7)
    var blob: Blob
    blob[0] = 1
    check contents.blobs.add(blob)
    for i in 0 ..< CELLS_PER_EXT_BLOB:
      check contents.kzg_proofs.add(default(KzgProof))

    for contentType in [jsonType, sszType]:
      let
        full = ContentBody(
          contentType: getContentType(contentType).get(),
          data: encodeBytes(contents, contentType).get())
        bare = ContentBody(
          contentType: getContentType(contentType).get(),
          data: encodeBytes(envelope, contentType).get())
        decodedFull = decodeBodyJsonOrSsz(
          PqSignedExecutionPayloadEnvelopeContents, full)
        decodedBare = decodeBodyJsonOrSsz(
          PqSignedExecutionPayloadEnvelope, bare)
      check:
        decodedFull.isOk()
        decodedFull.get() == contents
        decodedBare.isOk()
        decodedBare.get() == envelope

  test "Payload attestations one after another":
    var messages: seq[PqPayloadAttestationMessage]
    for i in 0 ..< 3:
      messages.add PqPayloadAttestationMessage(
        validator_index: uint64(i),
        data: PayloadAttestationData(
          beacon_block_root: Eth2Digest.fromHex("0x" & "66".repeat(32)),
          slot: 9.Slot, payload_present: true, blob_data_available: i == 1),
        signature: testSignature(byte(i)))

    let ssz = encodeBytes(messages, sszType).get()
    var concatenated: seq[byte]
    for message in messages:
      concatenated.add SSZ.encode(message)
    check:
      SSZ.encode(messages[0]).len == 2454
      ssz == concatenated

    for contentType in [jsonType, sszType]:
      let decoded = decodeBodyJsonOrSsz(
        seq[PqPayloadAttestationMessage],
        ContentBody(
          contentType: getContentType(contentType).get(),
          data: encodeBytes(messages, contentType).get()))
      check:
        decoded.isOk()
        decoded.get() == messages

    # Not a whole number of messages
    check decodeBodyJsonOrSsz(
      seq[PqPayloadAttestationMessage],
      ContentBody(
        contentType: getContentType(sszType).get(),
        data: ssz[0 ..< ssz.len - 1])).isErr()

  test "Proposer preferences one after another":
    var preferences: seq[PqSignedProposerPreferences]
    for i in 0 ..< 2:
      preferences.add PqSignedProposerPreferences(
        message: ProposerPreferences(
          dependent_root: Eth2Digest.fromHex("0x" & "77".repeat(32)),
          proposal_slot: Slot(40 + i), validator_index: uint64(i),
          target_gas_limit: 60_000_000),
        signature: testSignature(byte(i)))

    let ssz = encodeBytes(preferences, sszType).get()
    var concatenated: seq[byte]
    for item in preferences:
      concatenated.add SSZ.encode(item)
    check:
      SSZ.encode(preferences[0]).len == 2480
      ssz == concatenated

    for contentType in [jsonType, sszType]:
      let decoded = decodeBodyJsonOrSsz(
        seq[PqSignedProposerPreferences],
        ContentBody(
          contentType: getContentType(contentType).get(),
          data: encodeBytes(preferences, contentType).get()))
      check:
        decoded.isOk()
        decoded.get() == preferences

  test "Block header with an XMSS signature":
    let signature = testSignature(1)
    for hex in [signature.toHex(), "0x" & "aa".repeat(96)]:
      let
        body = "{\"execution_optimistic\":false,\"finalized\":false," &
          "\"data\":{\"root\":\"0x" & "88".repeat(32) &
          "\",\"canonical\":true,\"header\":{\"message\":{\"slot\":\"9\"," &
          "\"proposer_index\":\"7\",\"parent_root\":\"0x" & "00".repeat(32) &
          "\",\"state_root\":\"0x" & "00".repeat(32) &
          "\",\"body_root\":\"0x" & "00".repeat(32) &
          "\"},\"signature\":\"" & hex & "\"}}}"
        decoded = decodeBytes(
          GetBlockHeaderResponse, body.toBytes(),
          Opt.some(getContentType(jsonType).get()))
      check:
        decoded.isOk()
        decoded.get().data.header.message.slot == 9.Slot
        to0xHex(distinctBase(decoded.get().data.header.signature)) == hex
        RestJson.encode(decoded.get().data.header.signature) ==
          "\"" & hex & "\""
    expect SerializationError:
      discard RestJson.decode(
        "\"0x" & "aa".repeat(95) & "\"", RestBlockSignature)
