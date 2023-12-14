# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[typetraits, sequtils, sets],
  stew/[results, base10],
  chronicles,
  ./rest_utils,
  ./state_ttl_cache,
  ../beacon_node,
  ../consensus_object_pools/[blockchain_dag, exit_pool, spec_cache],
  ../spec/[deposit_snapshots, eth2_merkleization, forks, network, validator],
  ../spec/datatypes/[phase0, altair, deneb],
  ../validators/message_router_mev

export rest_utils

logScope: topics = "rest_beaconapi"

proc validateBeaconApiQueries*(key: string, value: string): int =
  ## This is rough validation procedure which should be simple and fast,
  ## because it will be used for query routing.
  case key
  of "{epoch}":
    0
  of "{slot}":
    0
  of "{peer_id}":
    0
  of "{state_id}":
    0
  of "{block_id}":
    0
  of "{validator_id}":
    0
  of "{block_root}":
    0
  of "{pubkey}":
    int(value.len != 98)
  else:
    1

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

proc installBeaconApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4881.md
  router.api(MethodGet, "/eth/v1/beacon/deposit_snapshot") do () -> RestApiResponse:
    let snapshot = node.db.getDepositTreeSnapshot().valueOr:
      # This can happen in a very short window after the client is started, but the
      # snapshot record still haven't been upgraded in the database. Returning 404
      # should be easy to handle for the clients - they just need to retry.
      return RestApiResponse.jsonError(Http404, NoFinalizedSnapshotAvailableError)

    return RestApiResponse.jsonResponse(
      RestDepositSnapshot(
        finalized: snapshot.depositContractState.branch,
        deposit_root: snapshot.getDepositRoot(),
        deposit_count: snapshot.getDepositCountU64(),
        execution_block_hash: snapshot.eth1Block,
        execution_block_height: snapshot.blockHeight))

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis
  router.api(MethodGet, "/eth/v1/beacon/genesis") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      (
        genesis_time: getStateField(node.dag.headState, genesis_time),
        genesis_validators_root:
          getStateField(node.dag.headState, genesis_validators_root),
        genesis_fork_version: node.dag.cfg.GENESIS_FORK_VERSION
      )
    )

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateRoot
  router.api(MethodGet, "/eth/v1/beacon/states/{state_id}/root") do (
    state_id: StateIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                         $error)

    node.withStateForBlockSlotId(bslot):
      return RestApiResponse.jsonResponseFinalized(
        (root: stateRoot),
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFork
  router.api(MethodGet, "/eth/v1/beacon/states/{state_id}/fork") do (
    state_id: StateIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    node.withStateForBlockSlotId(bslot):
      return RestApiResponse.jsonResponseFinalized(
        (
          previous_version:
            getStateField(state, fork).previous_version,
          current_version:
            getStateField(state, fork).current_version,
          epoch:
            getStateField(state, fork).epoch
        ),
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFinalityCheckpoints
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/finality_checkpoints") do (
    state_id: StateIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                         $error)

    node.withStateForBlockSlotId(bslot):
      return RestApiResponse.jsonResponseFinalized(
        (
          previous_justified:
            getStateField(state, previous_justified_checkpoint),
          current_justified:
            getStateField(state, current_justified_checkpoint),
          finalized:
            getStateField(state, finalized_checkpoint)
        ),
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  proc getIndices(
         node: BeaconNode,
         validatorIds: openArray[ValidatorIdent],
         state: ForkedHashedBeaconState
       ): Result[seq[ValidatorIndex], RestErrorMessage] =
    var
      keyset: HashSet[ValidatorPubKey]
      indexset: HashSet[ValidatorIndex]

    let validatorsCount = lenu64(getStateField(state, validators))

    for item in validatorIds:
      case item.kind
      of ValidatorQueryKind.Key:
        # Test for uniqueness of value.
        if keyset.containsOrIncl(item.key):
          return err(RestErrorMessage.init(
            Http400, NonUniqueValidatorIdError, $item.key))
      of ValidatorQueryKind.Index:
        let vindex = item.index.toValidatorIndex().valueOr:
          case error
          of ValidatorIndexError.TooHighValue:
            return err(RestErrorMessage.init(
              Http400, TooHighValidatorIndexValueError))
          of ValidatorIndexError.UnsupportedValue:
            return err(RestErrorMessage.init(
              Http500, UnsupportedValidatorIndexValueError))
        if uint64(vindex) < validatorsCount:
          # We're only adding validator indices which are present in
          # validators list at this moment.
          if indexset.containsOrIncl(vindex):
            return err(RestErrorMessage.init(
              Http400, NonUniqueValidatorIdError,
              Base10.toString(uint64(vindex))))

    if len(keyset) > 0:
      let optIndices = keysToIndices(node.restKeysCache, state, keyset.toSeq())
      # Remove all the duplicates.
      for item in optIndices:
        # We ignore missing keys.
        if item.isSome():
          indexset.incl(item.get())
    ok(indexset.toSeq())

  proc getValidators(
         node: BeaconNode,
         bslot: BlockSlotId,
         validatorsMask: ValidatorFilter,
         validatorIds: openArray[ValidatorIdent]
       ): RestApiResponse =
    node.withStateForBlockSlotId(bslot):
      let
        stateEpoch = getStateField(state, slot).epoch()
        indices = node.getIndices(validatorIds, state).valueOr:
          return RestApiResponse.jsonError(error)
        response =
          block:
            var res: seq[RestValidator]
            if len(indices) == 0:
              # Case when `len(indices) == 0 and len(validatorIds) != 0` means
              # that we can't find validator identifiers in state, so we should
              # return empty response.
              if len(validatorIds) == 0:
                # There are no indices, so we're going to filter all the
                # validators.
                for index, validator in getStateField(state, validators):
                  let
                    balance = getStateField(state, balances).item(index)
                    status = validator.getStatus(stateEpoch).valueOr:
                      return RestApiResponse.jsonError(
                        Http400, ValidatorStatusNotFoundError, $error)
                  if status in validatorsMask:
                    res.add(RestValidator.init(ValidatorIndex(index), balance,
                                               toString(status), validator))
            else:
              for index in indices:
                let
                  validator = getStateField(state, validators).item(index)
                  balance = getStateField(state, balances).item(index)
                  status = validator.getStatus(stateEpoch).valueOr:
                    return RestApiResponse.jsonError(
                      Http400, ValidatorStatusNotFoundError, $error)
                if status in validatorsMask:
                  res.add(RestValidator.init(index, balance, toString(status),
                                             validator))
            res
      return RestApiResponse.jsonResponseFinalized(
        response,
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )
    RestApiResponse.jsonError(Http404, StateNotFoundError)

  proc getBalances(
         node: BeaconNode,
         bslot: BlockSlotId,
         validatorIds: openArray[ValidatorIdent]
       ): RestApiResponse =
    node.withStateForBlockSlotId(bslot):
      let
        indices = node.getIndices(validatorIds, state).valueOr:
          return RestApiResponse.jsonError(error)
        response =
          block:
            var res: seq[RestValidatorBalance]
            if len(indices) == 0:
              # Case when `len(indices) == 0 and len(validatorIds) != 0` means
              # that we can't find validator identifiers in state, so we should
              # return empty response.
              if len(validatorIds) == 0:
                # There are no indices, so we're going to return balances of all
                # known validators.
                for index, balance in getStateField(state, balances):
                  res.add(RestValidatorBalance.init(ValidatorIndex(index),
                                                    balance))
            else:
              for index in indices:
                let balance = getStateField(state, balances).item(index)
                res.add(RestValidatorBalance.init(index, balance))
            res

      return RestApiResponse.jsonResponseFinalized(
        response,
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )
    RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
  router.api(MethodGet, "/eth/v1/beacon/states/{state_id}/validators") do (
    state_id: StateIdent, id: seq[ValidatorIdent],
    status: seq[ValidatorFilter]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(
          Http404, StateNotFoundError, $error)
      validatorIds =
        block:
          if id.isErr():
            return RestApiResponse.jsonError(
              Http400, InvalidValidatorIdValueError)
          let ires = id.get()
          if len(ires) > ServerMaximumValidatorIds:
            return RestApiResponse.jsonError(
              Http414, MaximumNumberOfValidatorIdsError)
          ires
      validatorsMask =
        block:
          if status.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidValidatorStatusValueError)
          validateFilter(status.get()).valueOr:
            return RestApiResponse.jsonError(
              Http400, InvalidValidatorStatusValueError, $error)
    getValidators(node, bslot, validatorsMask, validatorIds)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/postStateValidators
  router.api(MethodPost, "/eth/v1/beacon/states/{state_id}/validators") do (
    state_id: StateIdent, contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      (validatorIds, validatorsMask) =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let request =
            decodeBody(RestValidatorRequest, contentBody.get()).valueOr:
              return RestApiResponse.jsonError(
                Http400, InvalidRequestBodyError, $error)
          let
            ids = request.ids.valueOr: @[]
            filter = request.status.valueOr: {}
          (ids, filter)
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError, $error)
    getValidators(node, bslot, validatorsMask, validatorIds)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidator
  router.api(MethodGet,
          "/eth/v1/beacon/states/{state_id}/validators/{validator_id}") do (
    state_id: StateIdent, validator_id: ValidatorIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      vid = validator_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidValidatorIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    node.withStateForBlockSlotId(bslot):
      let
        current_epoch = getStateField(state, slot).epoch()
        validatorsCount = lenu64(getStateField(state, validators))

      let vindex =
        block:
          case vid.kind
          of ValidatorQueryKind.Key:
            let optIndices = keysToIndices(node.restKeysCache, state, [vid.key])
            if optIndices[0].isNone():
              return RestApiResponse.jsonError(Http404, ValidatorNotFoundError)
            optIndices[0].get()
          of ValidatorQueryKind.Index:
            let vres = vid.index.toValidatorIndex()
            if vres.isErr():
              case vres.error()
              of ValidatorIndexError.TooHighValue:
                return RestApiResponse.jsonError(Http400,
                                                TooHighValidatorIndexValueError)
              of ValidatorIndexError.UnsupportedValue:
                return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
            let index = vres.get()
            if uint64(index) >= validatorsCount:
              return RestApiResponse.jsonError(Http404, ValidatorNotFoundError)
            index

      let
        validator = getStateField(state, validators).item(vindex)
        balance = getStateField(state, balances).item(vindex)
        status =
          block:
            let sres = validator.getStatus(current_epoch)
            if sres.isErr():
              return RestApiResponse.jsonError(Http400,
                                               ValidatorStatusNotFoundError,
                                               $sres.get())
            toString(sres.get())
      return RestApiResponse.jsonResponseFinalized(
        RestValidator.init(vindex, balance, status, validator),
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidatorBalances
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/validator_balances") do (
    state_id: StateIdent, id: seq[ValidatorIdent]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError, $error)
      validatorIds =
        block:
          if id.isErr():
            return RestApiResponse.jsonError(
              Http400, InvalidValidatorIdValueError)
          let ires = id.get()
          if len(ires) > ServerMaximumValidatorIds:
            return RestApiResponse.jsonError(
              Http400, MaximumNumberOfValidatorIdsError)
          ires
    getBalances(node, bslot, validatorIds)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/postStateValidatorBalances
  router.api(MethodPost,
             "/eth/v1/beacon/states/{state_id}/validator_balances") do (
    state_id: StateIdent, contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      validatorIds =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let body = contentBody.get()
          decodeBody(seq[ValidatorIdent], body).valueOr:
            return RestApiResponse.jsonError(
              Http400, InvalidValidatorIdValueError, $error)
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError, $error)
    getBalances(node, bslot, validatorIds)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochCommittees
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/committees") do (
    state_id: StateIdent, epoch: Option[Epoch], index: Option[CommitteeIndex],
    slot: Option[Slot]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    let vepoch =
      if epoch.isSome():
        let repoch = epoch.get()
        if repoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $repoch.error())
        let res = repoch.get()

        if res > bslot.slot.epoch + MIN_SEED_LOOKAHEAD:
          return RestApiResponse.jsonError(
            Http400, InvalidEpochValueError,
            "Requested epoch more than 1 epoch past state epoch")

        if res + EPOCHS_PER_HISTORICAL_VECTOR <
            bslot.slot.epoch + MIN_SEED_LOOKAHEAD:
          return RestApiResponse.jsonError(
            Http400, InvalidEpochValueError,
            "Requested epoch earlier than what committees can be computed for")

        some(res)
      else:
        none[Epoch]()
    let vindex =
      if index.isSome():
        let rindex = index.get()
        if rindex.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidCommitteeIndexValueError,
                                           $rindex.error())
        some(rindex.get())
      else:
        none[CommitteeIndex]()
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           $rslot.error())
        let res = rslot.get()
        if vepoch.isSome():
          if res.epoch != vepoch.get():
            return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                             "Slot does not match requested epoch")
        else:
          if res.epoch > bslot.slot.epoch + 1:
            return RestApiResponse.jsonError(
              Http400, InvalidEpochValueError,
              "Requested slot more than 1 epoch past state epoch")

          if res.epoch + EPOCHS_PER_HISTORICAL_VECTOR <
              bslot.slot.epoch + MIN_SEED_LOOKAHEAD:
            return RestApiResponse.jsonError(
              Http400, InvalidEpochValueError,
              "Requested slot earlier than what committees can be computed for")

        some(res)
      else:
        none[Slot]()
    node.withStateForBlockSlotId(bslot):
      proc getCommittee(slot: Slot,
                        index: CommitteeIndex): RestBeaconStatesCommittees =
        let validators = get_beacon_committee(state, slot, index, cache)
        RestBeaconStatesCommittees(index: index, slot: slot,
                                   validators: validators)

      proc forSlot(slot: Slot, cindex: Option[CommitteeIndex],
                   res: var seq[RestBeaconStatesCommittees]) =
        let committees_per_slot = get_committee_count_per_slot(
          state, slot.epoch, cache)

        if cindex.isNone:
          for committee_index in get_committee_indices(committees_per_slot):
            res.add(getCommittee(slot, committee_index))
        else:
          let
            idx = cindex.get()
          if idx < committees_per_slot:
            res.add(getCommittee(slot, idx))

      var res: seq[RestBeaconStatesCommittees]
      let qepoch =
        if vepoch.isNone:
          epoch(getStateField(state, slot))
        else:
          vepoch.get()

      if vslot.isNone():
        for slot in qepoch.slots():
          forSlot(slot, vindex, res)
      else:
        forSlot(vslot.get(), vindex, res)

      return RestApiResponse.jsonResponseFinalized(
        res,
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochSyncCommittees
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/sync_committees") do (
    state_id: StateIdent, epoch: Option[Epoch]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    let qepoch =
      if epoch.isSome():
        let repoch = epoch.get()
        if repoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $repoch.error())
        let res = repoch.get()
        if res > MaxEpoch:
          return RestApiResponse.jsonError(Http400, EpochOverflowValueError)
        if res < node.dag.cfg.ALTAIR_FORK_EPOCH:
          return RestApiResponse.jsonError(Http400,
                                           EpochFromTheIncorrectForkError)
        res
      else:
        # If ``epoch`` not present then the sync committees for the epoch of
        # the state will be obtained.
        bslot.slot.epoch()

    node.withStateForBlockSlotId(bslot):
      let keys =
        block:
          let res = syncCommitteeParticipants(state, qepoch)
          if res.isErr():
            return RestApiResponse.jsonError(Http400,
                                             $res.error())
          let kres = res.get()
          if len(kres) == 0:
            return RestApiResponse.jsonError(Http500, InternalServerError,
                                 "List of sync committee participants is empty")
          kres

      let indices =
        block:
          var res: seq[ValidatorIndex]
          let optIndices = keysToIndices(node.restKeysCache, state, keys)
          # Remove all the duplicates.
          for item in optIndices:
            if item.isNone():
              # This should not be happened, because keys are from state.
              return RestApiResponse.jsonError(Http500, InternalServerError,
                                              "Could not get validator indices")
            res.add(item.get())
          res

      let aggregates =
        block:
          var
            res: seq[seq[ValidatorIndex]]
            offset = 0
          while true:
            let length = min(SYNC_SUBCOMMITTEE_SIZE, len(indices) - offset)
            if length == 0:
              break
            res.add(@(indices.toOpenArray(offset, offset + length - 1)))
            offset.inc(length)
          res

      return RestApiResponse.jsonResponseFinalized(
        RestEpochSyncCommittee(validators: indices,
                               validator_aggregates: aggregates),
        node.getStateOptimistic(state),
        node.dag.isFinalized(bslot.bid)
      )

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getStateRandao
  # https://github.com/ethereum/beacon-APIs/blob/b3c4defa238aaa74bf22aa602aa1b24b68a4c78e/apis/beacon/states/randao.yaml
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/randao") do (
    state_id: StateIdent, epoch: Option[Epoch]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlotId(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    let qepoch =
      if epoch.isSome():
        let repoch = epoch.get()
        if repoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $repoch.error())
        let res = repoch.get()
        if res > MaxEpoch:
          return RestApiResponse.jsonError(Http400, EpochOverflowValueError)
        if res < node.dag.cfg.ALTAIR_FORK_EPOCH:
          return RestApiResponse.jsonError(Http400,
                                           EpochFromTheIncorrectForkError)
        if res > bslot.slot.epoch() + 1:
          return RestApiResponse.jsonError(Http400,
                                           EpochFromFutureError)
        res
      else:
        # If ``epoch`` not present then the RANDAO mix for the epoch of
        # the state will be obtained.
        bslot.slot.epoch()

    # Try to obtain RANDAO in an accelerated way
    let bsi = node.dag.atSlot(bslot.bid, (qepoch + 1).start_slot - 1)
    if bsi.isSome:
      let mix = node.dag.computeRandaoMix(bsi.get.bid)
      if mix.isSome:
        return RestApiResponse.jsonResponseWOpt(
          RestEpochRandao(randao: mix.get),
          node.getBidOptimistic(bsi.get.bid)
        )

    # Fall back to full state computation
    node.withStateForBlockSlotId(bslot):
      withState(state):
        return RestApiResponse.jsonResponseFinalized(
          RestEpochRandao(randao: get_randao_mix(forkyState.data, qepoch)),
          node.getStateOptimistic(state),
          node.dag.isFinalized(bslot.bid)
        )

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeaders
  router.api(MethodGet, "/eth/v1/beacon/headers") do (
    slot: Option[Slot], parent_root: Option[Eth2Digest]) -> RestApiResponse:
    # TODO (cheatfate): This call is incomplete, because structure
    # of database do not allow to query blocks by `parent_root`.
    let qslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           $rslot.error())
        rslot.get()
      else:
        node.dag.head.slot

    if parent_root.isSome():
      let rroot = parent_root.get()
      if rroot.isErr():
        return RestApiResponse.jsonError(Http400, InvalidParentRootValueError,
                                         $rroot.error())
      return RestApiResponse.jsonError(Http500, NoImplementationError)

    let bdata = node.getForkedBlock(BlockIdent.init(qslot)).valueOr:
      return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    return
      withBlck(bdata):
        let bid = BlockId(root: forkyBlck.root, slot: forkyBlck.message.slot)
        RestApiResponse.jsonResponseFinalized(
          [
            (
              root: forkyBlck.root,
              canonical: node.dag.isCanonical(bid),
              header: (
                message: forkyBlck.toBeaconBlockHeader,
                signature: forkyBlck.signature
              )
            )
          ],
          node.getBlockOptimistic(bdata),
          node.dag.isFinalized(bid)
        )

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader
  router.api(MethodGet, "/eth/v1/beacon/headers/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bid = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

      bdata = node.getForkedBlock(bid).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    return
      withBlck(bdata):
        let bid = BlockId(root: forkyBlck.root, slot: forkyBlck.message.slot)
        RestApiResponse.jsonResponseFinalized(
          (
            root: forkyBlck.root,
            canonical: node.dag.isCanonical(bid),
            header: (
              message: forkyBlck.toBeaconBlockHeader,
              signature: forkyBlck.signature
            )
          ),
          node.getBlockOptimistic(bdata),
          node.dag.isFinalized(bid)
        )

  # https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock
  router.api(MethodPost, "/eth/v1/beacon/blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let res =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let
          body = contentBody.get()
          version = request.headers.getString("eth-consensus-version")
        var
          restBlock = decodeBody(RestPublishedSignedBlockContents, body,
                                 version).valueOr:
            return RestApiResponse.jsonError(error)
          forked = ForkedSignedBeaconBlock.init(restBlock)

        if restBlock.kind != node.dag.cfg.consensusForkAtEpoch(
             getForkedBlockField(forked, slot).epoch):
          doAssert strictVerification notin node.dag.updateFlags
          return RestApiResponse.jsonError(Http400, InvalidBlockObjectError)

        case restBlock.kind
        of ConsensusFork.Phase0:
          var blck = restBlock.phase0Data
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Altair:
          var blck = restBlock.altairData
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Bellatrix:
          var blck = restBlock.bellatrixData
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Capella:
          var blck = restBlock.capellaData
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Deneb:
          var blck = restBlock.denebData.signed_block
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.some(blck.create_blob_sidecars(
              restBlock.denebData.kzg_proofs, restBlock.denebData.blobs)))

    if res.isErr():
      return RestApiResponse.jsonError(
        Http503, BeaconNodeInSyncError, $res.error())
    if res.get().isNone():
      return RestApiResponse.jsonError(Http202, BlockValidationError)

    return RestApiResponse.jsonMsgResponse(BlockValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlockV2
  router.api(MethodPost, "/eth/v2/beacon/blocks") do (
    broadcast_validation: Option[BroadcastValidationType],
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let res =
      block:
        let
          version = request.headers.getString("eth-consensus-version")
          validation =
            block:
              let res =
                if broadcast_validation.isNone():
                  BroadcastValidationType.Gossip
                else:
                  broadcast_validation.get().valueOr:
                    return RestApiResponse.jsonError(Http400,
                      InvalidBroadcastValidationType)
              # TODO (henridf): support 'consensus' and
              # 'consensus_and_equivocation' broadcast_validation types.
              if res != BroadcastValidationType.Gossip:
                return RestApiResponse.jsonError(Http500,
                  "Only `gossip` broadcast_validation option supported")
              res
          body =
            block:
              if contentBody.isNone():
                return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
              contentBody.get()
        var
          restBlock = decodeBodyJsonOrSsz(RestPublishedSignedBlockContents,
                                          body, version).valueOr:
            return RestApiResponse.jsonError(error)
          forked = ForkedSignedBeaconBlock.init(restBlock)

        # TODO (henridf): handle broadcast_validation flag
        if restBlock.kind != node.dag.cfg.consensusForkAtEpoch(
             getForkedBlockField(forked, slot).epoch):
          doAssert strictVerification notin node.dag.updateFlags
          return RestApiResponse.jsonError(Http400, InvalidBlockObjectError)

        case restBlock.kind
        of ConsensusFork.Phase0:
          var blck = restBlock.phase0Data
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Altair:
          var blck = restBlock.altairData
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Bellatrix:
          var blck = restBlock.bellatrixData
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Capella:
          var blck = restBlock.capellaData
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.none(seq[BlobSidecar]))
        of ConsensusFork.Deneb:
          var blck = restBlock.denebData.signed_block
          blck.root = hash_tree_root(blck.message)
          await node.router.routeSignedBeaconBlock(
            blck, Opt.some(blck.create_blob_sidecars(
              restBlock.denebData.kzg_proofs, restBlock.denebData.blobs)))

    if res.isErr():
      return RestApiResponse.jsonError(
        Http503, BeaconNodeInSyncError, $res.error())
    if res.get().isNone():
      return RestApiResponse.jsonError(Http202, BlockValidationError)

    return RestApiResponse.jsonMsgResponse(BlockValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock
  # https://github.com/ethereum/beacon-APIs/blob/v2.4.0/apis/beacon/blocks/blinded_blocks.yaml
  router.api(MethodPost, "/eth/v1/beacon/blinded_blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    ## Instructs the beacon node to use the components of the
    ## `SignedBlindedBeaconBlock` to construct and publish a
    ## `SignedBeaconBlock` by swapping out the transactions_root for the
    ## corresponding full list of transactions. The beacon node should
    ## broadcast a newly constructed `SignedBeaconBlock` to the beacon network,
    ## to be included in the beacon chain. The beacon node is not required to
    ## validate the signed `BeaconBlock`, and a successful response (20X) only
    ## indicates that the broadcast has been successful.
    if contentBody.isNone():
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    let
      currentEpochFork =
        node.dag.cfg.consensusForkAtEpoch(node.currentSlot().epoch())
      version = request.headers.getString("eth-consensus-version")
      body = contentBody.get()

    if (body.contentType == OctetStreamMediaType) and
       (currentEpochFork.toString != version):
      return RestApiResponse.jsonError(Http400, BlockIncorrectFork)

    withConsensusFork(currentEpochFork):
      when consensusFork >= ConsensusFork.Capella:
        let
          restBlock = decodeBodyJsonOrSsz(
              consensusFork.SignedBlindedBeaconBlock, body).valueOr:
            return RestApiResponse.jsonError(error)
          payloadBuilderClient = node.getPayloadBuilderClient(
              restBlock.message.proposer_index).valueOr:
            return RestApiResponse.jsonError(
              Http400, "Unable to initialize payload builder client: " & $error)
          res = await node.unblindAndRouteBlockMEV(
            payloadBuilderClient, restBlock)

        if res.isErr():
          return RestApiResponse.jsonError(
            Http500, InternalServerError, $res.error())
        if res.get().isNone():
          return RestApiResponse.jsonError(Http202, BlockValidationError)

        return RestApiResponse.jsonMsgResponse(BlockValidationSuccess)
      elif consensusFork >= ConsensusFork.Bellatrix:
        return RestApiResponse.jsonError(
          Http400, $consensusFork & " builder API unsupported")
      else:
        # Pre-Bellatrix, this endpoint will accept a `SignedBeaconBlock`.
        #
        # This is mostly the same as /eth/v1/beacon/blocks for phase 0 and
        # altair.
        var
          restBlock = decodeBody(
              RestPublishedSignedBeaconBlock, body, version).valueOr:
            return RestApiResponse.jsonError(error)
          forked = ForkedSignedBeaconBlock(restBlock)

        if forked.kind != node.dag.cfg.consensusForkAtEpoch(
            getForkedBlockField(forked, slot).epoch):
          return RestApiResponse.jsonError(Http400, InvalidBlockObjectError)

        let res = withBlck(forked):
          forkyBlck.root = hash_tree_root(forkyBlck.message)
          await node.router.routeSignedBeaconBlock(
            forkyBlck, Opt.none(seq[BlobSidecar]))

        if res.isErr():
          return RestApiResponse.jsonError(
            Http503, BeaconNodeInSyncError, $res.error())
        elif res.get().isNone():
          return RestApiResponse.jsonError(Http202, BlockValidationError)

        return RestApiResponse.jsonMsgResponse(BlockValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlock
  router.api(MethodGet, "/eth/v1/beacon/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    return RestApiResponse.jsonError(
      Http410, DeprecatedRemovalBeaconBlocksDebugStateV1)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
  router.api(MethodGet, "/eth/v2/beacon/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      blockIdent = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)
      bid = node.getBlockId(blockIdent).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    return
      if contentType == sszMediaType:
        var data: seq[byte]
        if not node.dag.getBlockSSZ(bid, data):
          return RestApiResponse.jsonError(Http404, BlockNotFoundError)

        let
          fork = node.dag.cfg.consensusForkAtEpoch(bid.slot.epoch)
          headers = [("eth-consensus-version", fork.toString())]

        RestApiResponse.sszResponsePlain(data, headers)
      elif contentType == jsonMediaType:
        let bdata = node.dag.getForkedBlock(bid).valueOr:
          return RestApiResponse.jsonError(Http404, BlockNotFoundError)

        RestApiResponse.jsonResponseBlock(
          bdata.asSigned(),
          node.getBlockOptimistic(bdata),
          node.dag.isFinalized(bid)
        )
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot
  router.api(MethodGet, "/eth/v1/beacon/blocks/{block_id}/root") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      blockIdent = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

      bid = node.getBlockId(blockIdent).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

      bdata = node.dag.getForkedBlock(bid).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    return RestApiResponse.jsonResponseFinalized(
      (root: bid.root),
      node.getBlockOptimistic(bdata),
      node.dag.isFinalized(bid)
    )

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations
  router.api(MethodGet,
             "/eth/v1/beacon/blocks/{block_id}/attestations") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      blockIdent = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)
      bdata = node.getForkedBlock(blockIdent).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    return
      withBlck(bdata):
        let bid = BlockId(root: forkyBlck.root, slot: forkyBlck.message.slot)
        RestApiResponse.jsonResponseFinalized(
          forkyBlck.message.body.attestations.asSeq(),
          node.getBlockOptimistic(bdata),
          node.dag.isFinalized(bid)
        )

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolAttestations
  router.api(MethodGet, "/eth/v1/beacon/pool/attestations") do (
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]) -> RestApiResponse:
    let vindex =
      if committee_index.isSome():
        let rindex = committee_index.get()
        if rindex.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidCommitteeIndexValueError,
                                           $rindex.error())
        Opt.some(rindex.get())
      else:
        Opt.none(CommitteeIndex)
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           $rslot.error())
        Opt.some(rslot.get())
      else:
        Opt.none(Slot)
    var res: seq[Attestation]
    for item in node.attestationPool[].attestations(vslot, vindex):
      res.add(item)
    return RestApiResponse.jsonResponse(res)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttestations
  router.api(MethodPost, "/eth/v1/beacon/pool/attestations") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let attestations =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[Attestation], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidAttestationObjectError,
                                           $dres.error())
        dres.get()

    # Since our validation logic supports batch processing, we will submit all
    # attestations for validation.
    let pending =
      block:
        var res: seq[Future[SendResult]]
        for attestation in attestations:
          res.add(node.router.routeAttestation(attestation))
        res
    let failures =
      block:
        var res: seq[RestIndexedErrorMessageItem]
        await allFutures(pending)
        for index, future in pending:
          if future.completed():
            let fres = future.read()
            if fres.isErr():
              let failure = RestIndexedErrorMessageItem(index: index,
                                                        message: $fres.error())
              res.add(failure)
          elif future.failed() or future.cancelled():
            # This is unexpected failure, so we log the error message.
            let exc = future.readError()
            let failure = RestIndexedErrorMessageItem(index: index,
                                                      message: $exc.msg)
            res.add(failure)
        res

    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400, AttestationValidationError,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(AttestationValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolAttesterSlashings
  router.api(MethodGet, "/eth/v1/beacon/pool/attester_slashings") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      toSeq(node.validatorChangePool.attester_slashings))

  # https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttesterSlashings
  router.api(MethodPost, "/eth/v1/beacon/pool/attester_slashings") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let slashing =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(AttesterSlashing, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidAttesterSlashingObjectError,
                                           $dres.error())
        dres.get()
    let res = await node.router.routeAttesterSlashing(slashing)
    if res.isErr():
      return RestApiResponse.jsonError(Http400,
                                       AttesterSlashingValidationError,
                                       $res.error())
    return RestApiResponse.jsonMsgResponse(AttesterSlashingValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolProposerSlashings
  router.api(MethodGet, "/eth/v1/beacon/pool/proposer_slashings") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      toSeq(node.validatorChangePool.proposer_slashings))

  # https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolProposerSlashings
  router.api(MethodPost, "/eth/v1/beacon/pool/proposer_slashings") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let slashing =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(ProposerSlashing, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidProposerSlashingObjectError,
                                           $dres.error())
        dres.get()
    let res = await node.router.routeProposerSlashing(slashing)
    if res.isErr():
      return RestApiResponse.jsonError(Http400,
                                       ProposerSlashingValidationError,
                                       $res.error())
    return RestApiResponse.jsonMsgResponse(ProposerSlashingValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/getPoolBLSToExecutionChanges
  # https://github.com/ethereum/beacon-APIs/blob/86850001845df9163da5ae9605dbf15cd318d5d0/apis/beacon/pool/bls_to_execution_changes.yaml
  router.api(MethodGet, "/eth/v1/beacon/pool/bls_to_execution_changes") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      toSeq(node.validatorChangePool.bls_to_execution_changes_gossip) &
      toSeq(node.validatorChangePool.bls_to_execution_changes_api))

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/submitPoolBLSToExecutionChange
  # https://github.com/ethereum/beacon-APIs/blob/86850001845df9163da5ae9605dbf15cd318d5d0/apis/beacon/pool/bls_to_execution_changes.yaml
  router.api(MethodPost, "/eth/v1/beacon/pool/bls_to_execution_changes") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    if node.currentSlot().epoch() < node.dag.cfg.CAPELLA_FORK_EPOCH:
      return RestApiResponse.jsonError(Http400,
                                       InvalidBlsToExecutionChangeObjectError,
                                       "Attempt to add to BLS to execution change pool pre-Capella")
    let bls_to_execution_changes =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[SignedBLSToExecutionChange], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidBlsToExecutionChangeObjectError,
                                           $dres.error())
        dres.get()
    let res = await allFinished(mapIt(
      bls_to_execution_changes, node.router.routeBlsToExecutionChange(it)))
    for individual_res in res:
      doAssert individual_res.finished()
      if individual_res.failed():
        return RestApiResponse.jsonError(Http400,
                                         BlsToExecutionChangeValidationError,
                                         $individual_res.error[].msg)
      let fut_result = individual_res.read()
      if fut_result.isErr():
        return RestApiResponse.jsonError(Http400,
                                         BlsToExecutionChangeValidationError,
                                         $fut_result.error())
    return RestApiResponse.jsonMsgResponse(BlsToExecutionChangeValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolSyncCommitteeSignatures
  router.api(MethodPost, "/eth/v1/beacon/pool/sync_committees") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let messages =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[SyncCommitteeMessage], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                      InvalidSyncCommitteeSignatureMessageError)
        dres.get()

    let results = await node.router.routeSyncCommitteeMessages(messages)

    let failures =
      block:
        var res: seq[RestIndexedErrorMessageItem]
        for index, item in results:
          if item.isErr():
            res.add(RestIndexedErrorMessageItem(index: index,
                                                message: $item.error()))
        res
    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400,
                                           SyncCommitteeMessageValidationError,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(
        SyncCommitteeMessageValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolVoluntaryExits
  router.api(MethodGet, "/eth/v1/beacon/pool/voluntary_exits") do (
    ) -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      toSeq(node.validatorChangePool.voluntary_exits))

  # https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolVoluntaryExit
  router.api(MethodPost, "/eth/v1/beacon/pool/voluntary_exits") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let exit =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(SignedVoluntaryExit, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidVoluntaryExitObjectError,
                                           $dres.error())
        dres.get()
    let res = await node.router.routeSignedVoluntaryExit(exit)
    if res.isErr():
      return RestApiResponse.jsonError(Http400,
                                       VoluntaryExitValidationError,
                                       $res.error())
    return RestApiResponse.jsonMsgResponse(VoluntaryExitValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/?urls.primaryName=v2.4.2#/Beacon/getBlobSidecars
  # https://github.com/ethereum/beacon-APIs/blob/v2.4.2/apis/beacon/blob_sidecars/blob_sidecars.yaml
  router.api(MethodGet, "/eth/v1/beacon/blob_sidecars/{block_id}") do (
    block_id: BlockIdent, indices: seq[uint64]) -> RestApiResponse:
    let
      blockIdent = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)
      bid = node.getBlockId(blockIdent).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

      contentType = block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()

    # https://github.com/ethereum/beacon-APIs/blob/v2.4.2/types/deneb/blob_sidecar.yaml#L2-L28
    let data = newClone(default(List[BlobSidecar, Limit MAX_BLOBS_PER_BLOCK]))

    if indices.isErr:
      return RestApiResponse.jsonError(Http400,
                                       InvalidSidecarIndexValueError)

    let indexFilter = indices.get.toHashSet

    for blobIndex in 0'u64 ..< MAX_BLOBS_PER_BLOCK:
      if indexFilter.len > 0 and blobIndex notin indexFilter:
        continue

      var blobSidecar = new BlobSidecar

      if node.dag.db.getBlobSidecar(bid.root, blobIndex, blobSidecar[]):
        discard data[].add blobSidecar[]

    return
      if contentType == sszMediaType:
        RestApiResponse.sszResponse(
          data[], headers = [("eth-consensus-version",
            node.dag.cfg.consensusForkAtEpoch(bid.slot.epoch).toString())])
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponse(data)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)
