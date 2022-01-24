# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[typetraits, sequtils, strutils, sets],
  stew/[results, base10],
  chronicles,
  ./rest_utils,
  ../beacon_node, ../networking/eth2_network,
  ../consensus_object_pools/[blockchain_dag, exit_pool, spec_cache],
  ../validators/validator_duties,
  ../spec/[eth2_merkleization, forks, network, validator],
  ../spec/datatypes/[phase0, altair],
  ./state_ttl_cache

export rest_utils

logScope: topics = "rest_beaconapi"

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
  # https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis
  router.api(MethodGet, "/eth/v1/beacon/genesis") do () -> RestApiResponse:
    return RestApiResponse.jsonResponse(
      (
        genesis_time: getStateField(node.dag.headState.data, genesis_time),
        genesis_validators_root:
          getStateField(node.dag.headState.data, genesis_validators_root),
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
      bslot = node.getBlockSlot(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse((root: stateRoot))

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFork
  router.api(MethodGet, "/eth/v1/beacon/states/{state_id}/fork") do (
    state_id: StateIdent) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlot(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse(
        (
          previous_version:
            getStateField(stateData.data, fork).previous_version,
          current_version:
            getStateField(stateData.data, fork).current_version,
          epoch:
            getStateField(stateData.data, fork).epoch
        )
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
      bslot = node.getBlockSlot(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    node.withStateForBlockSlot(bslot):
      return RestApiResponse.jsonResponse(
        (
          previous_justified:
            getStateField(stateData.data, previous_justified_checkpoint),
          current_justified:
            getStateField(stateData.data, current_justified_checkpoint),
          finalized: getStateField(stateData.data, finalized_checkpoint)
        )
      )
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
  router.api(MethodGet, "/eth/v1/beacon/states/{state_id}/validators") do (
    state_id: StateIdent, id: seq[ValidatorIdent],
    status: seq[ValidatorFilter]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlot(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)
    let validatorIds =
      block:
        if id.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorIdValueError)
        let ires = id.get()
        if len(ires) > MaximumValidatorIds:
          return RestApiResponse.jsonError(Http400,
                                           MaximumNumberOfValidatorIdsError)
        ires

    let validatorsMask =
      block:
        if status.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorStatusValueError)
        let res = validateFilter(status.get())
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorStatusValueError,
                                           $res.error())
        res.get()

    node.withStateForBlockSlot(bslot):
      let
        current_epoch = getStateField(stateData.data, slot).epoch()
        validatorsCount = lenu64(getStateField(stateData.data, validators))

      let indices =
        block:
          var keyset: HashSet[ValidatorPubKey]
          var indexset: HashSet[ValidatorIndex]
          for item in validatorIds:
            case item.kind
            of ValidatorQueryKind.Key:
              keyset.incl(item.key)
            of ValidatorQueryKind.Index:
              let vindex =
                block:
                  let vres = item.index.toValidatorIndex()
                  if vres.isErr():
                    case vres.error()
                    of ValidatorIndexError.TooHighValue:
                      return RestApiResponse.jsonError(Http400,
                                                TooHighValidatorIndexValueError)
                    of ValidatorIndexError.UnsupportedValue:
                      return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
                  let index = vres.get()
                  index
              if uint64(vindex) < validatorsCount:
                # We only adding validator indices which are present in
                # validators list at this moment.
                indexset.incl(vindex)

          if len(keyset) > 0:
            let optIndices = keysToIndices(node.restKeysCache, stateData.data,
                                           keyset.toSeq())
            # Remove all the duplicates.
            for item in optIndices:
              # We ignore missing keys.
              if item.isSome():
                indexset.incl(item.get())
          indexset.toSeq()

      let response =
        block:
          var res: seq[RestValidator]
          if len(indices) == 0:
            # Case when `len(indices) == 0 and len(validatorIds) != 0` means
            # that we can't find validator identifiers in state, so we should
            # return empty response.
            if len(validatorIds) == 0:
              # There is no indices, so we going to filter all the validators.
              for index, validator in getStateField(stateData.data,
                                                    validators).pairs():
                let
                  balance = getStateField(stateData.data, balances).asSeq()[index]
                  status =
                    block:
                      let sres = validator.getStatus(current_epoch)
                      if sres.isErr():
                        return RestApiResponse.jsonError(Http400,
                                                     ValidatorStatusNotFoundError,
                                                     $sres.get())
                      sres.get()
                if status in validatorsMask:
                  res.add(RestValidator.init(ValidatorIndex(index), balance,
                                             toString(status), validator))
          else:
            for index in indices:
              let
                validator = getStateField(stateData.data, validators).asSeq()[index]
                balance = getStateField(stateData.data, balances).asSeq()[index]
                status =
                  block:
                    let sres = validator.getStatus(current_epoch)
                    if sres.isErr():
                      return RestApiResponse.jsonError(Http400,
                                                   ValidatorStatusNotFoundError,
                                                   $sres.get())
                    sres.get()
              if status in validatorsMask:
                res.add(RestValidator.init(index, balance, toString(status),
                                           validator))
          res
      return RestApiResponse.jsonResponse(response)
    return RestApiResponse.jsonError(Http404, StateNotFoundError)

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
      bslot = node.getBlockSlot(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    node.withStateForBlockSlot(bslot):
      let
        current_epoch = getStateField(stateData.data, slot).epoch()
        validatorsCount = lenu64(getStateField(stateData.data, validators))

      let vindex =
        block:
          let vid = validator_id.get()
          case vid.kind
          of ValidatorQueryKind.Key:
            let optIndices = keysToIndices(node.restKeysCache, stateData.data,
                                           [vid.key])
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
        validator = getStateField(stateData.data, validators).asSeq()[vindex]
        balance = getStateField(stateData.data, balances).asSeq()[vindex]
        status =
          block:
            let sres = validator.getStatus(current_epoch)
            if sres.isErr():
              return RestApiResponse.jsonError(Http400,
                                               ValidatorStatusNotFoundError,
                                               $sres.get())
            toString(sres.get())
      return RestApiResponse.jsonResponse(
        RestValidator.init(vindex, balance, status, validator)
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
      bslot = node.getBlockSlot(sid).valueOr:
        if sid.kind == StateQueryKind.Root:
          # TODO (cheatfate): Its impossible to retrieve state by `state_root`
          # in current version of database.
          return RestApiResponse.jsonError(Http500, NoImplementationError)
        return RestApiResponse.jsonError(Http404, StateNotFoundError,
                                          $error)

    let validatorIds =
      block:
        if id.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorIdValueError)
        let ires = id.get()
        if len(ires) > MaximumValidatorIds:
          return RestApiResponse.jsonError(Http400,
                                           MaximumNumberOfValidatorIdsError)
        ires

    node.withStateForBlockSlot(bslot):
      let validatorsCount = lenu64(getStateField(stateData.data, validators))

      let indices =
        block:
          var keyset: HashSet[ValidatorPubKey]
          var indexset: HashSet[ValidatorIndex]
          for item in validatorIds:
            case item.kind
            of ValidatorQueryKind.Key:
              keyset.incl(item.key)
            of ValidatorQueryKind.Index:
              let vindex =
                block:
                  let vres = item.index.toValidatorIndex()
                  if vres.isErr():
                    case vres.error()
                    of ValidatorIndexError.TooHighValue:
                      return RestApiResponse.jsonError(Http400,
                                                TooHighValidatorIndexValueError)
                    of ValidatorIndexError.UnsupportedValue:
                      return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
                  vres.get()
              # We only adding validator indices which are present in
              # validators list at this moment.
              if uint64(vindex) < validatorsCount:
                indexset.incl(vindex)

          if len(keyset) > 0:
            let optIndices = keysToIndices(node.restKeysCache, stateData.data,
                                           keyset.toSeq())
            # Remove all the duplicates.
            for item in optIndices:
              # We ignore missing keys.
              if item.isSome():
                indexset.incl(item.get())
          indexset.toSeq()

      let response =
        block:
          var res: seq[RestValidatorBalance]
          if len(indices) == 0:
            # Case when `len(indices) == 0 and len(validatorIds) != 0` means
            # that we can't find validator identifiers in state, so we should
            # return empty response.
            if len(validatorIds) == 0:
              # There is no indices, so we going to return balances of all
              # known validators.
              for index, balance in getStateField(stateData.data,
                                                    balances).pairs():
                res.add(RestValidatorBalance.init(ValidatorIndex(index),
                                                  balance))
          else:
            for index in indices:
              let balance = getStateField(stateData.data, balances).asSeq()[index]
              res.add(RestValidatorBalance.init(index, balance))
          res
      return RestApiResponse.jsonResponse(response)

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochCommittees
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/committees") do (
    state_id: StateIdent, epoch: Option[Epoch], index: Option[CommitteeIndex],
    slot: Option[Slot]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlot(sid).valueOr:
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
    node.withStateForBlockSlot(bslot):
      proc getCommittee(slot: Slot,
                        index: CommitteeIndex): RestBeaconStatesCommittees =
        let validators = get_beacon_committee(stateData.data, slot, index,
                                              cache)
        RestBeaconStatesCommittees(index: index, slot: slot,
                                   validators: validators)

      proc forSlot(slot: Slot, cindex: Option[CommitteeIndex],
                   res: var seq[RestBeaconStatesCommittees]) =
        let committees_per_slot = get_committee_count_per_slot(
          stateData.data, slot.epoch, cache)

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
          epoch(getStateField(stateData.data, slot))
        else:
          vepoch.get()

      if vslot.isNone():
        for slot in qepoch.slots():
          forSlot(slot, vindex, res)
      else:
        forSlot(vslot.get(), vindex, res)

      return RestApiResponse.jsonResponse(res)

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochSyncCommittees
  router.api(MethodGet,
             "/eth/v1/beacon/states/{state_id}/sync_committees") do (
    state_id: StateIdent, epoch: Option[Epoch]) -> RestApiResponse:
    let
      sid = state_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidStateIdValueError,
                                         $error)
      bslot = node.getBlockSlot(sid).valueOr:
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

    node.withStateForBlockSlot(bslot):
      let keys =
        block:
          let res = syncCommitteeParticipants(stateData().data, qepoch)
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
          let optIndices = keysToIndices(node.restKeysCache, stateData().data,
                                         keys)
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

      return RestApiResponse.jsonResponse(RestEpochSyncCommittee(
        validators: indices, validator_aggregates: aggregates)
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

    let blck =
      block:
        let res = node.getCurrentBlock(qslot)
        if res.isErr():
          return RestApiResponse.jsonError(Http404, BlockNotFoundError,
                                            $res.error())
        res.get()

    let bdata = node.dag.getForkedBlock(blck)
    return
      withBlck(bdata):
        RestApiResponse.jsonResponse(
          [
            (
              root: blck.root,
              canonical: node.dag.isCanonical(
                BlockId(root: blck.root, slot: blck.message.slot)),
              header: (
                message: (
                  slot: blck.message.slot,
                  proposer_index: blck.message.proposer_index,
                  parent_root: blck.message.parent_root,
                  state_root: blck.message.state_root,
                  body_root: blck.message.body.hash_tree_root()
                ),
                signature: blck.signature
              )
            )
          ]
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
        RestApiResponse.jsonResponse(
          (
            root: blck.root,
            canonical: node.dag.isCanonical(
              BlockId(root: blck.root, slot: blck.message.slot)),
            header: (
              message: (
                slot: blck.message.slot,
                proposer_index: blck.message.proposer_index,
                parent_root: blck.message.parent_root,
                state_root: blck.message.state_root,
                body_root: blck.message.body.hash_tree_root()
              ),
              signature: blck.signature
            )
          )
        )

  # https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock
  router.api(MethodPost, "/eth/v1/beacon/blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let forked =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let body = contentBody.get()
        let altairRes = decodeBody(altair.SignedBeaconBlock, body)
        if altairRes.isOk():
          var res = altairRes.get()
          if res.message.slot.epoch < node.dag.cfg.ALTAIR_FORK_EPOCH:
            # This message deserialized successfully as altair but should
            # actually be a phase0 block - try again with phase0
            let phase0res = decodeBody(phase0.SignedBeaconBlock, body)
            if phase0res.isOk():
              var res = phase0res.get()
              # `SignedBeaconBlock` deserialization do not update `root` field,
              # so we need to calculate it.
              res.root = hash_tree_root(res.message)
              ForkedSignedBeaconBlock.init(res)
            else:
              return RestApiResponse.jsonError(Http400, InvalidBlockObjectError,
                                              $phase0res.error())
          else:
            # `SignedBeaconBlock` deserialization do not update `root` field,
            # so we need to calculate it.
            res.root = hash_tree_root(res.message)
            ForkedSignedBeaconBlock.init(res)
        else:
          let phase0res = decodeBody(phase0.SignedBeaconBlock, body)
          if phase0res.isOk():
            var res = phase0res.get()
            # `SignedBeaconBlock` deserialization do not update `root` field,
            # so we need to calculate it.
            res.root = hash_tree_root(res.message)
            ForkedSignedBeaconBlock.init(res)
          else:
            return RestApiResponse.jsonError(Http400, InvalidBlockObjectError,
                                             $phase0res.error())

    let res = await node.sendBeaconBlock(forked)
    if res.isErr():
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
    if not(res.get()):
      return RestApiResponse.jsonError(Http202, BlockValidationError)

    return RestApiResponse.jsonMsgResponse(BlockValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlock
  router.api(MethodGet, "/eth/v1/beacon/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bid = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

      bdata = node.getForkedBlock(bid).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    let contentType =
      block:
        let res = preferredContentType("application/octet-stream",
                                       "application/json")
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    return
      case bdata.kind
      of BeaconBlockFork.Phase0:
        case contentType
        of "application/octet-stream":
          RestApiResponse.sszResponse(bdata.phase0Data)
        of "application/json":
          RestApiResponse.jsonResponse(bdata.phase0Data)
        else:
          RestApiResponse.jsonError(Http500, InvalidAcceptError)
      of BeaconBlockFork.Altair, BeaconBlockFork.Bellatrix:
        RestApiResponse.jsonError(Http404, BlockNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
  router.api(MethodGet, "/eth/v2/beacon/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bid = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

      bdata = node.getForkedBlock(bid).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)
    let contentType =
      block:
        let res = preferredContentType("application/octet-stream",
                                       "application/json")
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    return
      case contentType
      of "application/octet-stream":
        withBlck(bdata):
          RestApiResponse.sszResponse(blck)
      of "application/json":
        RestApiResponse.jsonResponsePlain(bdata.asSigned())
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot
  router.api(MethodGet, "/eth/v1/beacon/blocks/{block_id}/root") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bid = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

      blck = node.getBlockId(bid).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    return RestApiResponse.jsonResponse((root: blck.root))

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations
  router.api(MethodGet,
             "/eth/v1/beacon/blocks/{block_id}/attestations") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bid = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

      bdata = node.getForkedBlock(bid).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

    return
      withBlck(bdata):
        RestApiResponse.jsonResponse(blck.message.body.attestations.asSeq())

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
        some(rindex.get())
      else:
        none[CommitteeIndex]()
    let vslot =
      if slot.isSome():
        let rslot = slot.get()
        if rslot.isErr():
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           $rslot.error())
        some(rslot.get())
      else:
        none[Slot]()
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
          res.add(node.sendAttestation(attestation))
        res
    let failures =
      block:
        var res: seq[RestAttestationsFailure]
        await allFutures(pending)
        for index, future in pending.pairs():
          if future.done():
            let fres = future.read()
            if fres.isErr():
              let failure = RestAttestationsFailure(index: uint64(index),
                                                    message: $fres.error())
              res.add(failure)
          elif future.failed() or future.cancelled():
            # This is unexpected failure, so we log the error message.
            let exc = future.readError()
            let failure = RestAttestationsFailure(index: uint64(index),
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
    var res: seq[AttesterSlashing]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(res)
    let length = len(node.exitPool.attester_slashings)
    res = newSeqOfCap[AttesterSlashing](length)
    for item in node.exitPool.attester_slashings.items():
      res.add(item)
    return RestApiResponse.jsonResponse(res)

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
    let res = node.sendAttesterSlashing(slashing)
    if res.isErr():
      return RestApiResponse.jsonError(Http400,
                                       AttesterSlashingValidationError,
                                       $res.error())
    return RestApiResponse.jsonMsgResponse(AttesterSlashingValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolProposerSlashings
  router.api(MethodGet, "/eth/v1/beacon/pool/proposer_slashings") do (
    ) -> RestApiResponse:
    var res: seq[ProposerSlashing]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(res)
    let length = len(node.exitPool.proposer_slashings)
    res = newSeqOfCap[ProposerSlashing](length)
    for item in node.exitPool.proposer_slashings.items():
      res.add(item)
    return RestApiResponse.jsonResponse(res)

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
    let res = node.sendProposerSlashing(slashing)
    if res.isErr():
      return RestApiResponse.jsonError(Http400,
                                       ProposerSlashingValidationError,
                                       $res.error())
    return RestApiResponse.jsonMsgResponse(ProposerSlashingValidationSuccess)

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

    let results = await node.sendSyncCommitteeMessages(messages)

    let failures =
      block:
        var res: seq[RestAttestationsFailure]
        for index, item in results.pairs():
          if item.isErr():
            res.add(RestAttestationsFailure(index: uint64(index),
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
    var res: seq[SignedVoluntaryExit]
    if isNil(node.exitPool):
      return RestApiResponse.jsonResponse(res)
    let length = len(node.exitPool.voluntary_exits)
    res = newSeqOfCap[SignedVoluntaryExit](length)
    for item in node.exitPool.voluntary_exits.items():
      res.add(item)
    return RestApiResponse.jsonResponse(res)

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
    let res = node.sendVoluntaryExit(exit)
    if res.isErr():
      return RestApiResponse.jsonError(Http400,
                                       VoluntaryExitValidationError,
                                       $res.error())
    return RestApiResponse.jsonMsgResponse(VoluntaryExitValidationSuccess)

  # Legacy URLS - Nimbus <= 1.5.5 used to expose the REST API with an additional
  # `/api` path component
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/genesis",
    "/eth/v1/beacon/genesis",
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/root",
    "/eth/v1/beacon/states/{state_id}/root",
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/fork",
    "/eth/v1/beacon/states/{state_id}/fork",
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/finality_checkpoints",
    "/eth/v1/beacon/states/{state_id}/finality_checkpoints"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/validators",
    "/eth/v1/beacon/states/{state_id}/validators"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
    "/eth/v1/beacon/states/{state_id}/validators/{validator_id}"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/validator_balances",
    "/eth/v1/beacon/states/{state_id}/validator_balances"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/committees",
    "/eth/v1/beacon/states/{state_id}/committees"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/states/{state_id}/sync_committees",
    "/eth/v1/beacon/states/{state_id}/sync_committees"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/headers",
    "/eth/v1/beacon/headers"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/headers/{block_id}",
    "/eth/v1/beacon/headers/{block_id}"
  )
  router.redirect(
    MethodPost,
    "/api/eth/v1/beacon/blocks",
    "/eth/v1/beacon/blocks"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/blocks/{block_id}",
    "/eth/v1/beacon/blocks/{block_id}"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v2/beacon/blocks/{block_id}",
    "/eth/v2/beacon/blocks/{block_id}"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/blocks/{block_id}/root",
    "/eth/v1/beacon/blocks/{block_id}/root"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/blocks/{block_id}/attestations",
    "/eth/v1/beacon/blocks/{block_id}/attestations"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/pool/attestations",
    "/eth/v1/beacon/pool/attestations"
  )
  router.redirect(
    MethodPost,
    "/api/eth/v1/beacon/pool/attestations",
    "/eth/v1/beacon/pool/attestations"
  )
  router.redirect(
    MethodPost,
    "/api/eth/v1/beacon/pool/attester_slashings",
    "/eth/v1/beacon/pool/attester_slashings"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/pool/attester_slashings",
    "/eth/v1/beacon/pool/attester_slashings"
  )
  router.redirect(
    MethodPost,
    "/api/eth/v1/beacon/pool/proposer_slashings",
    "/eth/v1/beacon/pool/proposer_slashings"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/pool/proposer_slashings",
    "/eth/v1/beacon/pool/proposer_slashings"
  )
  router.redirect(
    MethodPost,
    "/api/eth/v1/beacon/pool/sync_committees",
    "/eth/v1/beacon/pool/sync_committees"
  )
  router.redirect(
    MethodPost,
    "/api/eth/v1/beacon/pool/voluntary_exits",
    "/eth/v1/beacon/pool/voluntary_exits"
  )
  router.redirect(
    MethodGet,
    "/api/eth/v1/beacon/pool/voluntary_exits",
    "/eth/v1/beacon/pool/voluntary_exits"
  )
