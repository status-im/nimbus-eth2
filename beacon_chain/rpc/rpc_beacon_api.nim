# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[parseutils, sequtils, strutils, sets],
  stew/[byteutils, results],
  json_rpc/servers/httpserver,
  chronicles,
  ../beacon_node,
  ../networking/eth2_network,
  ../validators/validator_duties,
  ../consensus_object_pools/blockchain_dag,
  ../spec/[eth2_merkleization, forks, network, validator],
  ../spec/datatypes/[phase0],
  ./rpc_utils

logScope: topics = "beaconapi"

type
  RpcServer = RpcHttpServer

  ValidatorQuery = object
    keyset: HashSet[ValidatorPubKey]
    ids: seq[uint64]

  StatusQuery = object
    statset: HashSet[string]

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

proc parsePubkey(str: string): ValidatorPubKey {.raises: [Defect, ValueError].} =
  const expectedLen = RawPubKeySize * 2 + 2
  if str.len != expectedLen: # +2 because of the `0x` prefix
    raise newException(ValueError,
      "A hex public key should be exactly " & $expectedLen & " characters. " &
      $str.len & " provided")
  let pubkeyRes = fromHex(ValidatorPubKey, str)
  if pubkeyRes.isErr:
    raise newException(ValueError, "Not a valid public key")
  return pubkeyRes[]

proc createIdQuery(ids: openArray[string]): Result[ValidatorQuery, string] =
  # validatorIds array should have maximum 30 items, and all items should be
  # unique.
  if len(ids) > 30:
    return err("The number of ids exceeds the limit")

  # All ids in validatorIds must be unique.
  if len(ids) != len(toHashSet(ids)):
    return err("ids array must have unique item")

  var res = ValidatorQuery(
    keyset: initHashSet[ValidatorPubKey](),
    ids: newSeq[uint64]()
  )

  for item in ids:
    if item.startsWith("0x"):
      if len(item) != RawPubKeySize * 2 + 2:
        return err("Incorrect hexadecimal key")
      let pubkeyRes = ValidatorPubKey.fromHex(item)
      if pubkeyRes.isErr:
        return err("Incorrect public key")
      res.keyset.incl(pubkeyRes.get())
    else:
      var tmp: uint64
      try:
        if parseBiggestUInt(item, tmp) != len(item):
          return err("Incorrect index value")
      except ValueError:
        return err("Cannot parse index value: " & item)
      res.ids.add(tmp)
  ok(res)

proc createStatusQuery(status: openArray[string]): Result[StatusQuery, string] =
  const AllowedStatuses = [
    "pending", "pending_initialized", "pending_queued",
    "active", "active_ongoing", "active_exiting", "active_slashed",
    "exited", "exited_unslashed", "exited_slashed",
    "withdrawal", "withdrawal_possible", "withdrawal_done"
  ]

  if len(status) > len(AllowedStatuses):
    return err("The number of statuses exceeds the limit")

  var res = StatusQuery(statset: initHashSet[string]())

  # All ids in validatorIds must be unique.
  if len(status) != len(toHashSet(status)):
    return err("Status array must have unique items")

  for item in status:
    if item notin AllowedStatuses:
      return err("Invalid status requested")
    case item
    of "pending":
      res.statset.incl("pending_initialized")
      res.statset.incl("pending_queued")
    of "active":
      res.statset.incl("active_ongoing")
      res.statset.incl("active_exiting")
      res.statset.incl("active_slashed")
    of "exited":
      res.statset.incl("exited_unslashed")
      res.statset.incl("exited_slashed")
    of "withdrawal":
      res.statset.incl("withdrawal_possible")
      res.statset.incl("withdrawal_done")
    else:
      res.statset.incl(item)

proc getStatus(validator: Validator,
               current_epoch: Epoch): Result[string, string] =
  if validator.activation_epoch > current_epoch:
    # pending
    if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH:
      ok("pending_initialized")
    else:
      # validator.activation_eligibility_epoch < FAR_FUTURE_EPOCH:
      ok("pending_queued")
  elif (validator.activation_epoch <= current_epoch) and
       (current_epoch < validator.exit_epoch):
    # active
    if validator.exit_epoch == FAR_FUTURE_EPOCH:
      ok("active_ongoing")
    elif not validator.slashed:
      # validator.exit_epoch < FAR_FUTURE_EPOCH
      ok("active_exiting")
    else:
      # validator.exit_epoch < FAR_FUTURE_EPOCH and validator.slashed:
      ok("active_slashed")
  elif (validator.exit_epoch <= current_epoch) and
       (current_epoch < validator.withdrawable_epoch):
    # exited
    if not validator.slashed:
      ok("exited_unslashed")
    else:
      # validator.slashed
      ok("exited_slashed")
  elif validator.withdrawable_epoch <= current_epoch:
    # withdrawal
    if validator.effective_balance != 0:
      ok("withdrawal_possible")
    else:
      # validator.effective_balance == 0
      ok("withdrawal_done")
  else:
    err("Invalid validator status")

proc getForkedBlockFromBlockId(
    node: BeaconNode, blockId: string): ForkedTrustedSignedBeaconBlock {.
    raises: [Defect, CatchableError].} =
  case blockId:
    of "head":
      node.dag.getForkedBlock(node.dag.head)
    of "genesis":
      node.dag.getForkedBlock(node.dag.genesis)
    of "finalized":
      node.dag.getForkedBlock(node.dag.finalizedHead.blck)
    else:
      if blockId.startsWith("0x"):
        let
          blckRoot = parseRoot(blockId)
        node.dag.getForkedBlock(blckRoot).valueOr:
          raise newException(CatchableError, "Block not found")
      else:
        let bid = node.getBlockIdFromString(blockId)
        node.dag.getForkedBlock(bid).valueOr:
          raise newException(CatchableError, "Block not found")

proc installBeaconApiHandlers*(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Defect, CatchableError].} =
  rpcServer.rpc("get_v1_beacon_genesis") do () -> RpcBeaconGenesis:
    return (
      genesis_time: getStateField(node.dag.headState.data, genesis_time),
      genesis_validators_root:
        getStateField(node.dag.headState.data, genesis_validators_root),
      genesis_fork_version: node.dag.cfg.GENESIS_FORK_VERSION
    )

  rpcServer.rpc("get_v1_beacon_states_root") do (stateId: string) -> Eth2Digest:
    withStateForStateId(stateId):
      return stateRoot

  rpcServer.rpc("get_v1_beacon_states_fork") do (stateId: string) -> Fork:
    withStateForStateId(stateId):
      return getStateField(stateData.data, fork)

  rpcServer.rpc("get_v1_beacon_states_finality_checkpoints") do (
      stateId: string) -> RpcBeaconStatesFinalityCheckpoints:
    withStateForStateId(stateId):
      return (previous_justified:
                getStateField(stateData.data, previous_justified_checkpoint),
              current_justified:
                getStateField(stateData.data, current_justified_checkpoint),
              finalized: getStateField(stateData.data, finalized_checkpoint))

  rpcServer.rpc("get_v1_beacon_states_stateId_validators") do (
      stateId: string, validatorIds: Option[seq[string]],
      status: Option[seq[string]]) -> seq[RpcBeaconStatesValidators]:
    var vquery: ValidatorQuery
    var squery: StatusQuery
    let current_epoch = getStateField(node.dag.headState.data, slot).epoch

    template statusCheck(status, statusQuery, vstatus, current_epoch): bool =
      if status.isNone():
        true
      else:
        if vstatus in squery.statset:
          true
        else:
          false

    var res: seq[RpcBeaconStatesValidators]

    withStateForStateId(stateId):
      if status.isSome:
        let sqres = createStatusQuery(status.get())
        if sqres.isErr:
          raise newException(CatchableError, sqres.error)
        squery = sqres.get()

      if validatorIds.isSome:
        let vqres = createIdQuery(validatorIds.get())
        if vqres.isErr:
          raise newException(CatchableError, vqres.error)
        vquery = vqres.get()

      if validatorIds.isNone():
        for index, validator in getStateField(stateData.data, validators).pairs():
          let sres = validator.getStatus(current_epoch)
          if sres.isOk:
            let vstatus = sres.get()
            let includeFlag = statusCheck(status, squery, vstatus,
                                          current_epoch)
            if includeFlag:
              res.add((validator: validator,
                       index: uint64(index),
                       status: vstatus,
                       balance: getStateField(stateData.data, balances).asSeq()[index]))
      else:
        for index in vquery.ids:
          if index < lenu64(getStateField(stateData.data, validators)):
            let validator = getStateField(stateData.data, validators).asSeq()[index]
            let sres = validator.getStatus(current_epoch)
            if sres.isOk:
              let vstatus = sres.get()
              let includeFlag = statusCheck(status, squery, vstatus,
                                            current_epoch)
              if includeFlag:
                vquery.keyset.excl(validator.pubkey)
                res.add((validator: validator,
                         index: uint64(index),
                         status: vstatus,
                         balance: getStateField(stateData.data, balances).asSeq()[index]))

        for index, validator in getStateField(stateData.data, validators).pairs():
          if validator.pubkey in vquery.keyset:
            let sres = validator.getStatus(current_epoch)
            if sres.isOk:
              let vstatus = sres.get()
              let includeFlag = statusCheck(status, squery, vstatus,
                                            current_epoch)
              if includeFlag:
                res.add((validator: validator,
                         index: uint64(index),
                         status: vstatus,
                         balance: getStateField(stateData.data, balances).asSeq()[index]))
    return res

  rpcServer.rpc("get_v1_beacon_states_stateId_validators_validatorId") do (
      stateId: string, validatorId: string) -> RpcBeaconStatesValidators:
    let current_epoch = getStateField(node.dag.headState.data, slot).epoch
    let vqres = createIdQuery([validatorId])
    if vqres.isErr:
      raise newException(CatchableError, vqres.error)
    let vquery = vqres.get()

    withStateForStateId(stateId):
      if len(vquery.ids) > 0:
        let index = vquery.ids[0]
        if index < lenu64(getStateField(stateData.data, validators)):
          let validator = getStateField(stateData.data, validators).asSeq()[index]
          let sres = validator.getStatus(current_epoch)
          if sres.isOk:
            return (validator: validator, index: uint64(index),
                    status: sres.get(),
                    balance: getStateField(stateData.data, balances).asSeq()[index])
          else:
            raise newException(CatchableError, "Incorrect validator's state")
      else:
        for index, validator in getStateField(stateData.data, validators).pairs():
          if validator.pubkey in vquery.keyset:
            let sres = validator.getStatus(current_epoch)
            if sres.isOk:
              return (validator: validator, index: uint64(index),
                      status: sres.get(),
                      balance: getStateField(stateData.data, balances).asSeq()[index])
            else:
              raise newException(CatchableError, "Incorrect validator's state")

  rpcServer.rpc("get_v1_beacon_states_stateId_validator_balances") do (
      stateId: string, validatorsId: Option[seq[string]]) -> seq[RpcBalance]:

    var res: seq[RpcBalance]
    withStateForStateId(stateId):
      if validatorsId.isNone():
        for index, value in getStateField(stateData.data, balances).pairs():
          let balance = (index: uint64(index), balance: value)
          res.add(balance)
      else:
        let vqres = createIdQuery(validatorsId.get())
        if vqres.isErr:
          raise newException(CatchableError, vqres.error)

        var vquery = vqres.get()
        for index in vquery.ids:
          if index < lenu64(getStateField(stateData.data, validators)):
            let validator = getStateField(stateData.data, validators).asSeq()[index]
            vquery.keyset.excl(validator.pubkey)
            let balance = (index: uint64(index),
                           balance: getStateField(stateData.data, balances).asSeq()[index])
            res.add(balance)

        for index, validator in getStateField(stateData.data, validators).pairs():
          if validator.pubkey in vquery.keyset:
            let balance = (index: uint64(index),
                           balance: getStateField(stateData.data, balances).asSeq()[index])
            res.add(balance)
    return res

  rpcServer.rpc("get_v1_beacon_states_stateId_committees_epoch") do (
      stateId: string, epoch: Option[uint64], index: Option[uint64],
      slot: Option[uint64]) -> seq[RpcBeaconStatesCommittees]:
    withStateForStateId(stateId):
      proc getCommittee(slot: Slot,
                        index: CommitteeIndex): RpcBeaconStatesCommittees =
        let vals = get_beacon_committee(
          stateData.data, slot, index, cache).mapIt(it.uint64)
        return (index: index.uint64, slot: slot.uint64, validators: vals)

      proc forSlot(slot: Slot, res: var seq[RpcBeaconStatesCommittees]) =
        let committees_per_slot =
          get_committee_count_per_slot(stateData.data, slot.epoch, cache)

        if index.isNone:
          for committee_index in get_committee_indices(committees_per_slot):
            res.add(getCommittee(slot, committee_index))
        else:
          if index.get() < committees_per_slot:
            let cindex = CommitteeIndex.init(index.get()).expect(
              "valid because verified against committees_per_slot")
            res.add(getCommittee(slot, cindex))

      var res: seq[RpcBeaconStatesCommittees]

      let qepoch =
        if epoch.isNone:
          epoch(getStateField(stateData.data, slot))
        else:
          Epoch(epoch.get())

      if slot.isNone:
        for slot in qepoch.slots():
          forSlot(slot, res)
      else:
        forSlot(Slot(slot.get()), res)

      return res

  rpcServer.rpc("get_v1_beacon_headers") do (
      slot: Option[uint64], parent_root: Option[string]) ->
      seq[RpcBeaconHeaders]:
    unimplemented()

  rpcServer.rpc("get_v1_beacon_headers_blockId") do (
      blockId: string) ->
      tuple[canonical: bool, header: SignedBeaconBlockHeader]:
    let bd = node.getForkedBlockFromBlockId(blockId)
    return withBlck(bd):
      static: doAssert blck.signature is TrustedSig and
                sizeof(ValidatorSig) == sizeof(blck.signature)
      (
        canonical: node.dag.isCanonical(
          BlockId(root: blck.root, slot: blck.message.slot)),
        header: SignedBeaconBlockHeader(
          message: BeaconBlockHeader(
            slot: blck.message.slot,
            proposer_index: blck.message.proposer_index,
            parent_root: blck.message.parent_root,
            state_root: blck.message.state_root,
            body_root: blck.message.body.hash_tree_root()
          )
        )
      )

  rpcServer.rpc("post_v1_beacon_blocks") do (blck: phase0.SignedBeaconBlock) -> int:
    let res = await sendBeaconBlock(node, ForkedSignedBeaconBlock.init(blck))
    if res.isErr():
      raise (ref CatchableError)(msg: $res.error())

    if res.get():
      # The block was validated successfully and has been broadcast.
      # It has also been integrated into the beacon node's database.
      return 200
    else:
      # The block failed validation, but was successfully broadcast anyway.
      # It was not integrated into the beacon node''s database.
      return 202

  rpcServer.rpc("get_v1_beacon_blocks_blockId") do (
      blockId: string) -> phase0.TrustedSignedBeaconBlock:
    let blck = node.getForkedBlockFromBlockId(blockId)
    if blck.kind == BeaconBlockFork.Phase0:
      return blck.phase0Data
    else:
      raiseNoAltairSupport()

  rpcServer.rpc("get_v1_beacon_blocks_blockId_root") do (
      blockId: string) -> Eth2Digest:
    return withBlck(node.getForkedBlockFromBlockId(blockId)):
      blck.root

  rpcServer.rpc("get_v1_beacon_blocks_blockId_attestations") do (
      blockId: string) -> seq[TrustedAttestation]:
    return withBlck(node.getForkedBlockFromBlockId(blockId)):
      blck.message.body.attestations.asSeq

  rpcServer.rpc("get_v1_beacon_pool_attestations") do (
      slot: Option[uint64], committee_index: Option[uint64]) ->
      seq[RpcAttestation]:

    var res: seq[RpcAttestation]

    let qslot =
      if slot.isSome():
        some(Slot(slot.get()))
      else:
        none[Slot]()

    let qindex =
      if committee_index.isSome():
        some(CommitteeIndex(committee_index.get()))
      else:
        none[CommitteeIndex]()

    for item in node.attestationPool[].attestations(qslot, qindex):
      let atuple = (
        aggregation_bits: to0xHex(item.aggregation_bits.bytes),
        data: item.data,
        signature: item.signature
      )
      res.add(atuple)

    return res

  rpcServer.rpc("post_v1_beacon_pool_attestations") do (
      attestation: Attestation) -> bool:
    let res = await node.sendAttestation(attestation)
    if not res.isOk():
      raise (ref CatchableError)(msg: $res.error())
    return true

  rpcServer.rpc("get_v1_beacon_pool_attester_slashings") do (
      ) -> seq[AttesterSlashing]:
    var res: seq[AttesterSlashing]
    if isNil(node.exitPool):
      return res
    let length = len(node.exitPool.attester_slashings)
    res = newSeqOfCap[AttesterSlashing](length)
    for item in node.exitPool.attester_slashings.items():
      res.add(item)
    return res

  rpcServer.rpc("post_v1_beacon_pool_attester_slashings") do (
      slashing: AttesterSlashing) -> bool:
    let res = node.sendAttesterSlashing(slashing)
    if not res.isOk():
      raise (ref CatchableError)(msg: $res.error())
    return true

  rpcServer.rpc("get_v1_beacon_pool_proposer_slashings") do (
      ) -> seq[ProposerSlashing]:
    var res: seq[ProposerSlashing]
    if isNil(node.exitPool):
      return res
    let length = len(node.exitPool.proposer_slashings)
    res = newSeqOfCap[ProposerSlashing](length)
    for item in node.exitPool.proposer_slashings.items():
      res.add(item)
    return res

  rpcServer.rpc("post_v1_beacon_pool_proposer_slashings") do (
      slashing: ProposerSlashing) -> bool:
    let res = node.sendProposerSlashing(slashing)
    if not res.isOk():
      raise (ref CatchableError)(msg: $res.error())
    return true

  rpcServer.rpc("get_v1_beacon_pool_voluntary_exits") do (
      ) -> seq[SignedVoluntaryExit]:
    var res: seq[SignedVoluntaryExit]
    if isNil(node.exitPool):
      return res
    let length = len(node.exitPool.voluntary_exits)
    res = newSeqOfCap[SignedVoluntaryExit](length)
    for item in node.exitPool.voluntary_exits.items():
      res.add(item)
    return res

  rpcServer.rpc("post_v1_beacon_pool_voluntary_exits") do (
      exit: SignedVoluntaryExit) -> bool:
    let res = node.sendVoluntaryExit(exit)
    if not res.isOk():
      raise (ref CatchableError)(msg: $res.error())
    return true
