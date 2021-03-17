# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[typetraits, sequtils, strutils, deques, sets, options],
  stew/[results, base10],
  chronicles,
  nimcrypto/utils as ncrutils,
  ../beacon_node_common, ../networking/eth2_network,
  ../consensus_object_pools/[blockchain_dag, exit_pool],
  ../spec/[crypto, digest, validator],
  ../ssz/merkleization,
  ./rest_utils

import ../spec/datatypes except readValue, writeValue

logScope: topics = "rest_beaconapi"

type
  ValidatorTuple = tuple
    index: ValidatorIndex
    balance: string
    status: string
    validator: Validator

  ValidatorBalanceTuple = tuple
    index: ValidatorIndex
    balance: string

  StateCommitteeTuple = tuple
    index: CommitteeIndex
    slot: Slot
    validators: seq[ValidatorIndex]

  # # BlockHeaderMessageTuple = tuple
  # #   slot: Slot
  # #   proposer_index: string
  # #   parent_root: Eth2Digest
  # #   state_root: Eth2Digest
  # #   body_root: Eth2Digest

  # # SignedHeaderMessageTuple = tuple
  # #   message: BlockHeaderMessageTuple
  # #   signature: ValidatorSig

  # # BlockHeaderTuple = tuple
  # #   root: Eth2Digest
  # #   canonical: bool
  # #   header: SignedHeaderMessageTuple

proc validateFilter(filters: seq[ValidatorFilter]): Result[ValidatorFilter,
                                                           cstring] =
  var res: ValidatorFilter
  for item in filters:
    if res * item != {}:
      return err("Validator status must be unique")
    res.incl(item)

  if res == {}:
    res = {ValidatorFilterKind.PendingInitialized,
           ValidatorFilterKind.PendingQueued,
           ValidatorFilterKind.ActiveOngoing,
           ValidatorFilterKind.ActiveExiting,
           ValidatorFilterKind.ActiveSlashed,
           ValidatorFilterKind.ExitedUnslashed,
           ValidatorFilterKind.ExitedSlashed,
           ValidatorFilterKind.WithdrawalPossible,
           ValidatorFilterKind.WithdrawalDone}
  ok(res)

proc getStatus(validator: Validator,
               current_epoch: Epoch): Result[ValidatorFilterKind, cstring] =
  if validator.activation_epoch > current_epoch:
    # pending
    if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH:
      ok(ValidatorFilterKind.PendingInitialized)
    else:
      # validator.activation_eligibility_epoch < FAR_FUTURE_EPOCH:
      ok(ValidatorFilterKind.PendingQueued)
  elif (validator.activation_epoch <= current_epoch) and
       (current_epoch < validator.exit_epoch):
    # active
    if validator.exit_epoch == FAR_FUTURE_EPOCH:
      ok(ValidatorFilterKind.ActiveOngoing)
    elif not validator.slashed:
      # validator.exit_epoch < FAR_FUTURE_EPOCH
      ok(ValidatorFilterKind.ActiveExiting)
    else:
      # validator.exit_epoch < FAR_FUTURE_EPOCH and validator.slashed:
      ok(ValidatorFilterKind.ActiveSlashed)
  elif (validator.exit_epoch <= current_epoch) and
       (current_epoch < validator.withdrawable_epoch):
    # exited
    if not validator.slashed:
      ok(ValidatorFilterKind.ExitedUnslashed)
    else:
      # validator.slashed
      ok(ValidatorFilterKind.ExitedSlashed)
  elif validator.withdrawable_epoch <= current_epoch:
    # withdrawal
    if validator.effective_balance != 0:
      ok(ValidatorFilterKind.WithdrawalPossible)
    else:
      # validator.effective_balance == 0
      ok(ValidatorFilterKind.WithdrawalDone)
  else:
    err("Invalid validator status")

proc toString*(digest: Eth2Digest): string =
  "0x" & ncrutils.toHex(digest.data, true)

proc toString*(version: Version): string =
  "0x" & ncrutils.toHex(cast[array[4, byte]](version))

proc toString*(kind: ValidatorFilterKind): string =
  case kind
  of ValidatorFilterKind.PendingInitialized:
    "pending_initialized"
  of ValidatorFilterKind.PendingQueued:
    "pending_queued"
  of ValidatorFilterKind.ActiveOngoing:
    "active_ongoing"
  of ValidatorFilterKind.ActiveExiting:
    "active_exiting"
  of ValidatorFilterKind.ActiveSlashed:
    "active_slashed"
  of ValidatorFilterKind.ExitedUnslashed:
    "exited_unslashed"
  of ValidatorFilterKind.ExitedSlashed:
    "exited_slashed"
  of ValidatorFilterKind.WithdrawalPossible:
    "withdrawal_possible"
  of ValidatorFilterKind.WithdrawalDone:
    "withdrawal_done"

proc `%`*(s: Epoch): JsonNode = newJString(Base10.toString(uint64(s)))
proc `%`*(s: Slot): JsonNode = newJString(Base10.toString(uint64(s)))
proc `%`*(s: uint64): JsonNode = newJString(Base10.toString(s))
proc `%`*(s: ValidatorIndex): JsonNode = newJString(Base10.toString(uint64(s)))
proc `%`*(s: CommitteeIndex): JsonNode = newJString(Base10.toString(uint64(s)))
proc `%`*(s: Checkpoint): JsonNode = %(epoch: s.epoch, root: s.root)
proc `%`*(s: GraffitiBytes): JsonNode =
  newJString("0x" & ncrutils.toHex(distinctBase(s), true))
proc `%`*(s: ValidatorSig): JsonNode =
  newJString("0x" & ncrutils.toHex(toRaw(s), true))
proc `%`*(pubkey: ValidatorPubKey): JsonNode =
  newJString("0x" & ncrutils.toHex(toRaw(pubkey), true))
proc `%`*(digest: Eth2Digest): JsonNode =
  newJString("0x" & ncrutils.toHex(digest.data, true))
proc `%`*(bitlist: BitList): JsonNode =
  newJString("0x" & ncrutils.toHex(seq[byte](BitSeq(bitlist)), true))
proc `%`*(s: Validator): JsonNode =
  let activation_eligibility_epoch =
    if s.activation_eligibility_epoch < 1:
      FarFutureEpochString
    else:
      Base10.toString(uint64(s.activation_eligibility_epoch))
  let activation_epoch =
    if s.activation_epoch < 1:
      FarFutureEpochString
    else:
      Base10.toString(uint64(s.activation_epoch))
  let exit_epoch =
    if s.exit_epoch < 1:
      FarFutureEpochString
    else:
      Base10.toString(uint64(s.exit_epoch))
  let withdrawable_epoch =
    if s.withdrawable_epoch < 1:
      FarFutureEpochString
    else:
      Base10.toString(uint64(s.withdrawable_epoch))
  %(
    pubkey: s.pubkey,
    withdrawal_credentials: s.withdrawal_credentials,
    effective_balance: Base10.toString(s.effective_balance),
    slashed: s.slashed,
    activation_eligibility_epoch: activation_eligibility_epoch,
    activation_epoch: activation_epoch,
    exit_epoch: exit_epoch,
    withdrawable_epoch: withdrawable_epoch
  )
proc `%`*(s: AttestationData): JsonNode =
  %(
    slot: s.slot,
    index: Base10.toString(s.index),
    beacon_block_root: s.beacon_block_root,
    source: s.source,
    target: s.target
  )
proc `%`*(s: TrustedAttestation): JsonNode =
  %(
    aggregation_bits: s.aggregation_bits,
    signature: cast[ValidatorSig](s.signature),
    data: s.data
  )
proc `%`*(s: Attestation): JsonNode =
  %(
    aggregation_bits: s.aggregation_bits,
    signature: s.signature,
    data: s.data
  )
proc `%`*(s: VoluntaryExit): JsonNode =
  %(epoch: s.epoch, validator_index: Base10.toString(s.validator_index))
proc `%`*(s: SignedVoluntaryExit): JsonNode =
  %(message: s.message, signature: s.signature)
proc `%`*(s: DepositData): JsonNode =
  %(
    pubkey: s.pubkey,
    withdrawal_credentials: s.withdrawal_credentials,
    amount: Base10.toString(s.amount),
    signature: s.signature
  )
proc `%`*(s: Deposit): JsonNode =
  %(proof: s.proof, data: s.data)
proc `%`*(s: BeaconBlockHeader): JsonNode =
  %(
    slot: s.slot,
    proposer_index: Base10.toString(s.proposer_index),
    parent_root: s.parent_root,
    state_root: s.state_root,
    body_root: s.body_root,
  )
proc `%`*(s: SignedBeaconBlockHeader): JsonNode =
  %(message: s.message, signature: s.signature)
proc `%`*(s: ProposerSlashing): JsonNode =
  %(signed_header_1: s.signed_header_1, signed_header_2: s.signed_header_2)
proc `%`*(s: IndexedAttestation): JsonNode =
  %(
    attesting_indices: s.attesting_indices,
    data: s.data,
    signature: s.signature
  )
proc `%`*(s: AttesterSlashing): JsonNode =
  %(attestation_1: s.attestation_1, attestation_2: s.attestation_2)
proc `%`*(s: Eth1Data): JsonNode =
  %(
    deposit_root: s.deposit_root,
    deposit_count: Base10.toString(s.deposit_count),
    block_hash: s.block_hash
  )
proc `%`*(s: TrustedBeaconBlockBody): JsonNode =
  %(
    randao_reveal: cast[ValidatorSig](s.randao_reveal),
    graffiti: s.graffiti,
    proposer_slashings: s.proposer_slashings,
    attester_slashings: s.attester_slashings,
    attestations: s.attestations,
    deposits: s.deposits,
    voluntary_exits: s.voluntary_exits
  )
proc `%`*(s: TrustedBeaconBlock): JsonNode =
  %(
    slot: s.slot,
    proposer_index: Base10.toString(s.proposer_index),
    parent_root: s.parent_root,
    state_root: s.state_root,
    body: s.body
  )
proc `%`*(s: TrustedSignedBeaconBlock): JsonNode =
  %(message: s.message, signature: cast[ValidatorSig](s.signature))

proc readValue*(reader: var JsonReader, value: var ValidatorSig)
               {.raises: [IOError, SerializationError, Defect].} =
  let hexValue = reader.readValue(string)
  let res = ValidatorSig.fromHex(hexValue)
  if res.isOk():
    value = res.get()
  else:
    reader.raiseUnexpectedValue($res.error())

proc readValue*(reader: var JsonReader, value: var Epoch)
               {.raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    value = Epoch(res.get())
  else:
    reader.raiseUnexpectedValue($res.error())

proc readValue*(reader: var JsonReader, value: var Slot)
               {.raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    value = Slot(res.get())
  else:
    reader.raiseUnexpectedValue($res.error())

# proc readValue*(reader: var JsonReader, value: var ValidatorIndex)
#                {.raises: [IOError, SerializationError, Defect].} =
#   let svalue = reader.readValue(string)
#   let res = Base10.decode(uint64, svalue)
#   if res.isOk():
#     let v = res.get()
#     if v < VALIDATOR_REGISTRY_LIMIT:
#       value = ValidatorIndex(v)
#     else:
#       reader.raiseUnexpectedValue(
#         "Validator index is bigger then VALIDATOR_REGISTRY_LIMIT")
#   else:
#     reader.raiseUnexpectedValue($res.error())

proc decodeBody*[T](t: typedesc[T],
                    body: ContentBody): Result[T, cstring] =
  if body.contentType != "application/json":
    return err("Unsupported content type")
  warn "Decoding data", data = cast[string](body.data)
  let data =
    try:
      Json.decode(cast[string](body.data), T)
    except SerializationError as exc:
      warn "Error happens while processing json", errMsg = exc.formatMsg("tmp.nim")
      return err("Unable to process data")
    except CatchableError as exc:
      warn "Error happens while parsing json", exc = exc.name, excMsg = exc.msg
      return err("Unable to parse application/json data")
  ok(data)

proc installBeaconApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getGenesis
  router.api(MethodGet, "/api/eth/v1/beacon/genesis") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      %(
        genesis_time: toString(node.chainDag.headState.data.data.genesis_time),
        genesis_validators_root:
          node.chainDag.headState.data.data.genesis_validators_root,
        genesis_fork_version: node.runtimePreset.GENESIS_FORK_VERSION
      )
    )

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateRoot
  router.api(MethodGet, "/api/eth/v1/beacon/states/{state_id}/root") do (
    state_id: StateIdent) -> RestApiResponse:
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      return RestApiResponse.jsonResponse(%(root: hashedState().root))
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFork
  router.api(MethodGet, "/api/eth/v1/beacon/states/{state_id}/fork") do (
    state_id: StateIdent) -> RestApiResponse:
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      return RestApiResponse.jsonResponse(
        %(
          previous_version: state().fork.previous_version,
          current_version: state().fork.current_version,
          epoch: state().fork.epoch
        )
      )
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFinalityCheckpoints
  router.api(MethodGet,
             "/api/eth/v1/beacon/states/{state_id}/finality_checkpoints") do (
    state_id: StateIdent) -> RestApiResponse:
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      return RestApiResponse.jsonResponse(
        %(
           previous_justified: state().previous_justified_checkpoint,
           current_justified: state().current_justified_checkpoint,
           finalized: state().finalized_checkpoint
        )
      )
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidators
  router.api(MethodGet, "/api/eth/v1/beacon/states/{state_id}/validators") do (
    state_id: StateIdent, id: seq[ValidatorIdent],
    status: seq[ValidatorFilter]) -> RestApiResponse:
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let validatorIds =
      block:
        if id.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator identifier(s)")
        id.get()

    let validatorsMask =
      block:
        if status.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator status(es)")
        let res = validateFilter(status.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator status value",
                                           $res.error())
        res.get()

    let (keySet, indexSet) =
      block:
        var res1: HashSet[ValidatorPubKey]
        var res2: HashSet[ValidatorIndex]
        for item in validatorIds:
          case item.kind
          of ValidatorQueryKind.Key:
            if item.key in res1:
              return RestApiResponse.jsonError(Http400,
                                           "Only unique validator keys allowed")
            res1.incl(item.key)
          of ValidatorQueryKind.Index:
            if item.index in res2:
              return RestApiResponse.jsonError(Http400,
                                        "Only unique validator indexes allowed")
            res2.incl(item.index)
        (res1, res2)

    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())

    node.withStateForStateIdent(bres.get()):
      let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
      var res: seq[ValidatorTuple]
      for index, validator in state().validators.pairs():
        let r1 =
          if len(keySet) == 0:
            true
          else:
            (validator.pubkey in keySet)
        let r2 =
          if len(indexSet) == 0:
            true
          else:
            (ValidatorIndex(index) in indexSet)
        let sres = validator.getStatus(current_epoch)
        if sres.isOk():
          let vstatus = sres.get()
          let r3 = vstatus in validatorsMask
          if (r1 or r2) and r3:
            res.add((
              index: ValidatorIndex(index),
              balance: Base10.toString(state().balances[index]),
              status: toString(vstatus),
              validator: validator
            ))
      return RestApiResponse.jsonResponse(%res)

    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidator
  router.api(MethodGet,
          "/api/eth/v1/beacon/states/{state_id}/validators/{validator_id}") do (
    state_id: StateIdent, validator_id: ValidatorIdent) -> RestApiResponse:
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    if validator_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid validator_id",
                                       $validator_id.error())

    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
      let vid = validator_id.get()
      case vid.kind
      of ValidatorQueryKind.Key:
        for index, validator in state().validators.pairs():
          if validator.pubkey == vid.key:
            let sres = validator.getStatus(current_epoch)
            if sres.isOk():
              return RestApiResponse.jsonResponse(
                %(
                  index: ValidatorIndex(index),
                  balance: Base10.toString(state().balances[index]),
                  status: toString(sres.get()),
                  validator: validator
                )
              )
            else:
              return RestApiResponse.jsonError(Http400,
                                          "Could not obtain validator's status")
        return RestApiResponse.jsonError(Http404, "Could not find validator")
      of ValidatorQueryKind.Index:
        let index = uint64(vid.index)
        if index >= uint64(len(state().validators)):
          return RestApiResponse.jsonError(Http404, "Could not find validator")
        let validator = state().validators[index]
        let sres = validator.getStatus(current_epoch)
        if sres.isOk():
          return RestApiResponse.jsonResponse(
            %(
              index: ValidatorIndex(index),
              balance: Base10.toString(state().balances[index]),
              status: toString(sres.get()),
              validator: validator
            )
          )
        else:
          return RestApiResponse.jsonError(Http400,
                                          "Could not obtain validator's status")
    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidatorBalances
  router.api(MethodGet,
             "/api/eth/v1/beacon/states/{state_id}/validator_balances") do (
    state_id: StateIdent, id: seq[ValidatorIdent]) -> RestApiResponse:
    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let validatorIds =
      block:
        if id.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid validator identifier(s)")
        id.get()

    let (keySet, indexSet) =
      block:
        var res1: HashSet[ValidatorPubKey]
        var res2: HashSet[ValidatorIndex]
        for item in validatorIds:
          case item.kind
          of ValidatorQueryKind.Key:
            if item.key in res1:
              return RestApiResponse.jsonError(Http400,
                                           "Only unique validator keys allowed")
            res1.incl(item.key)
          of ValidatorQueryKind.Index:
            if item.index in res2:
              return RestApiResponse.jsonError(Http400,
                                        "Only unique validator indexes allowed")
            res2.incl(item.index)
        (res1, res2)

    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
      var res: seq[ValidatorBalanceTuple]
      for index, validator in state().validators.pairs():
        let rflag =
          if (len(keySet) == 0) and (len(indexSet) == 0):
            true
          else:
            (validator.pubkey in keySet) or (ValidatorIndex(index) in indexSet)
        let sres = validator.getStatus(current_epoch)
        if sres.isOk():
          let vstatus = sres.get()
          if rflag:
            res.add((
              index: ValidatorIndex(index),
              balance: Base10.toString(state().balances[index]),
            ))
      return RestApiResponse.jsonResponse(%res)

    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getEpochCommittees
  router.api(MethodGet,
             "/api/eth/v1/beacon/states/{state_id}/committees") do (
    state_id: StateIdent, epoch: Option[Epoch], index: Option[CommitteeIndex],
    slot: Option[Slot]) -> RestApiResponse:

    if state_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid state_id",
                                       $state_id.error())
    let vepoch =
      if epoch.isSome():
        let repoch = epoch.get()
        if repoch.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid epoch value",
                                           $repoch.error())
        some(repoch.get())
      else:
        none[Epoch]()
    let vindex =
      if index.isSome():
        let rindex = index.get()
        if rindex.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid index value",
                                           $rindex.error())
        some(rindex.get())
      else:
        none[CommitteeIndex]()
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid slot value",
                                           $rslot.error())
        some(rslot.get())
      else:
        none[Slot]()

    let bres = node.getBlockSlot(state_id.get())
    if bres.isErr():
      return RestApiResponse.jsonError(Http404, "State not found",
                                       $bres.error())
    node.withStateForStateIdent(bres.get()):
      proc getCommittee(slot: Slot,
                        index: CommitteeIndex): StateCommitteeTuple =
        let validators = get_beacon_committee(state, slot, index,
                                              cache).mapIt(it)
        (index: index, slot: slot, validators: validators)

      proc forSlot(slot: Slot, cindex: Option[CommitteeIndex],
                   res: var seq[StateCommitteeTuple]) =
        let committees_per_slot =
          get_committee_count_per_slot(state, Epoch(slot), cache)

        if cindex.isNone:
          for committee_index in 0'u64 ..< committees_per_slot:
            res.add(getCommittee(slot, CommitteeIndex(committee_index)))
        else:
          let idx = cindex.get()
          if uint64(idx) < committees_per_slot:
            res.add(getCommittee(slot, CommitteeIndex(idx)))

      var res: seq[StateCommitteeTuple]
      let qepoch =
        if vepoch.isNone:
          compute_epoch_at_slot(state().slot)
        else:
          vepoch.get()

      if vslot.isNone():
        for i in 0 ..< SLOTS_PER_EPOCH:
          forSlot(compute_start_slot_at_epoch(qepoch) + i, vindex, res)
      else:
        forSlot(vslot.get(), vindex, res)

      return RestApiResponse.jsonResponse(%res)

    return RestApiResponse.jsonError(Http500, "Internal server error")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeaders
  router.api(MethodGet, "/api/eth/v1/beacon/headers") do (
    slot: Option[Slot], parent_root: Option[Eth2Digest]) -> RestApiResponse:
    return RestApiResponse.jsonError(Http500, "Not implemented yet")

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeader
  router.api(MethodGet, "/api/eth/v1/beacon/headers/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    if block_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                       $block_id.error())
    let res = node.getBlockDataFromBlockIdent(block_id.get())
    if res.isErr():
      return RestApiResponse.jsonError(Http404, "Block not found")

    let data = res.get()
    return RestApiResponse.jsonResponse(
      %(
        root: data.data.root,
        canonical: data.refs.isAncestorOf(node.chainDag.head),
        header: (
          message: (
            slot: data.data.message.slot,
            proposer_index: Base10.toString(data.data.message.proposer_index),
            parent_root: data.data.message.parent_root,
            state_root: data.data.message.state_root,
            body_root: data.data.message.body.hash_tree_root()
          ),
          signature: cast[ValidatorSig](data.data.signature)
        )
      )
    )

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/publishBlock
  router.api(MethodPost, "/api/eth/v1/beacon/blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    discard

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlock
  router.api(MethodGet, "/api/eth/v1/beacon/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    if block_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                       $block_id.error())
    let res = node.getBlockDataFromBlockIdent(block_id.get())
    if res.isErr():
      return RestApiResponse.jsonError(Http404, "Block not found")
    let data = res.get()
    return RestApiResponse.jsonResponse(%(data.data))

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockRoot
  router.api(MethodGet, "/api/eth/v1/beacon/blocks/{block_id}/root") do (
    block_id: BlockIdent) -> RestApiResponse:
    if block_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                       $block_id.error())
    let res = node.getBlockDataFromBlockIdent(block_id.get())
    if res.isErr():
      return RestApiResponse.jsonError(Http404, "Block not found")
    let data = res.get()
    return RestApiResponse.jsonResponse(%(root: data.data.root))

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockAttestations
  router.api(MethodGet,
             "/api/eth/v1/beacon/blocks/{block_id}/attestations") do (
    block_id: BlockIdent) -> RestApiResponse:
    if block_id.isErr():
      return RestApiResponse.jsonError(Http400, "Invalid block_id",
                                       $block_id.error())
    let res = node.getBlockDataFromBlockIdent(block_id.get())
    if res.isErr():
      return RestApiResponse.jsonError(Http404, "Block not found")
    let data = res.get()
    return RestApiResponse.jsonResponse(
      %data.data.message.body.attestations.asSeq()
    )

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttestations
  router.api(MethodGet, "/api/eth/v1/beacon/pool/attestations") do (
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]) -> RestApiResponse:
    let vindex =
      if committee_index.isSome():
        let rindex = committee_index.get()
        if rindex.isErr():
          return RestApiResponse.jsonError(Http400,
                                           "Invalid committee_index value",
                                           $rindex.error())
        some(rindex.get())
      else:
        none[CommitteeIndex]()
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, "Invalid slot value",
                                           $rslot.error())
        some(rslot.get())
      else:
        none[Slot]()

    var res: seq[Attestation]
    for item in node.attestationPool[].attestations(vslot, vindex):
      res.add(item)
    return RestApiResponse.jsonResponse(%res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttestations
  router.api(MethodPost, "/api/eth/v1/beacon/pool/attestations") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    discard

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttesterSlashings
  router.api(MethodGet, "/api/eth/v1/beacon/pool/attester_slashings") do (
    ) -> RestApiResponse:
    var res: seq[AttesterSlashing]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(%res)
    let length = len(node.exitPool.attester_slashings)
    res = newSeqOfCap[AttesterSlashing](length)
    for item in node.exitPool.attester_slashings.items():
      res.add(item)
    return RestApiResponse.jsonResponse(%res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttesterSlashings
  router.api(MethodPost, "/api/eth/v1/beacon/pool/attester_slashings") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    discard

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolProposerSlashings
  router.api(MethodGet, "/api/eth/v1/beacon/pool/proposer_slashings") do (
    ) -> RestApiResponse:
    var res: seq[ProposerSlashing]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(%res)
    let length = len(node.exitPool.proposer_slashings)
    res = newSeqOfCap[ProposerSlashing](length)
    for item in node.exitPool.proposer_slashings.items():
      res.add(item)
    return RestApiResponse.jsonResponse(%res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolProposerSlashings
  router.api(MethodPost, "/api/eth/v1/beacon/pool/proposer_slashings") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    discard

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolVoluntaryExits
  router.api(MethodGet, "/api/eth/v1/beacon/pool/voluntary_exits") do (
    ) -> RestApiResponse:
    var res: seq[SignedVoluntaryExit]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(%res)
    let length = len(node.exitPool.voluntary_exits)
    res = newSeqOfCap[SignedVoluntaryExit](length)
    for item in node.exitPool.voluntary_exits.items():
      res.add(item)
    return RestApiResponse.jsonResponse(%res)

  # https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolVoluntaryExit
  router.api(MethodPost, "/api/eth/v1/beacon/pool/voluntary_exits") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    if contentBody.isNone():
      return RestApiResponse.jsonError(Http400, "Empty request's body")
    let res = decodeBody(SignedVoluntaryExit, contentBody.get())
    warn "VoluntaryExit received", value = $res.get()
