import
  std/[options, tables],
  metrics, chronicles,
  ../spec/[crypto, beaconstate, forks, helpers, presets],
  ../spec/datatypes/[phase0, altair],
  ../beacon_clock

logScope: topics = "val_mon"

# Validator monitoring based on the same feature in Lighthouse - using the same
# metrics allows users to more easily reuse monitoring setups

declareGauge validator_monitor_balance_gwei,
  "The validator's balance in gwei.", labels = ["validator"]
declareGauge validator_monitor_effective_balance_gwei,
  "The validator's effective balance in gwei.", labels = ["validator"]
declareGauge validator_monitor_slashed,
  "Set to 1 if the validator is slashed.", labels = ["validator"]
declareGauge validator_monitor_active,
  "Set to 1 if the validator is active.", labels = ["validator"]
declareGauge validator_monitor_exited,
  "Set to 1 if the validator is exited.", labels = ["validator"]
declareGauge validator_monitor_withdrawable,
  "Set to 1 if the validator is withdrawable.", labels = ["validator"]
declareGauge validator_activation_eligibility_epoch,
  "Set to the epoch where the validator will be eligible for activation.", labels = ["validator"]
declareGauge validator_activation_epoch,
  "Set to the epoch where the validator will activate.", labels = ["validator"]
declareGauge validator_exit_epoch,
  "Set to the epoch where the validator will exit.", labels = ["validator"]
declareGauge validator_withdrawable_epoch,
  "Set to the epoch where the validator will be withdrawable.", labels = ["validator"]

declareCounter validator_monitor_prev_epoch_on_chain_attester_hit,
  "Incremented if the validator is flagged as a previous epoch attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_head_attester_hit,
  "Incremented if the validator is flagged as a previous epoch head attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_head_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch head attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_target_attester_hit,
  "Incremented if the validator is flagged as a previous epoch target attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_target_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch target attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_source_attester_hit,
  "Incremented if the validator is flagged as a previous epoch source attester during per epoch processing", labels = ["validator"]
declareCounter validator_monitor_prev_epoch_on_chain_source_attester_miss,
  "Incremented if the validator is not flagged as a previous epoch source attester during per epoch processing", labels = ["validator"]

declareGauge validator_monitor_prev_epoch_attestations_total,
  "The number of unagg. attestations seen in the previous epoch.", labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_attestations_min_delay_seconds,
  "The min delay between when the validator should send the attestation and when it was received.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attestation_aggregate_inclusions,
  "The count of times an attestation was seen inside an aggregate.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attestation_block_inclusions,
  "The count of times an attestation was seen inside a block.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attestation_block_min_inclusion_distance,
  "The minimum inclusion distance observed for the inclusion of an attestation in a block.", labels = ["validator"]

declareGauge validator_monitor_prev_epoch_aggregates_total,
  "The number of aggregates seen in the previous epoch.", labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_aggregates_min_delay_seconds,
  "The min delay between when the validator should send the aggregate and when it was received.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_exits_total,
  "The number of exits seen in the previous epoch.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_proposer_slashings_total,
  "The number of proposer slashings seen in the previous epoch.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_attester_slashings_total,
  "The number of attester slashings seen in the previous epoch.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_committee_messages_total,
  "The number of sync committee messages seen in the previous epoch.", labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_sync_committee_messages_min_delay_seconds,
  "The min delay between when the validator should send the sync committee message and when it was received.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_contribution_inclusions,
  "The count of times a sync signature was seen inside a sync contribution.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_signature_block_inclusions,
  "The count of times a sync signature was seen inside a block.", labels = ["validator"]
declareGauge validator_monitor_prev_epoch_sync_contributions_total,
  "The number of sync contributions seen in the previous epoch.", labels = ["validator"]
declareHistogram validator_monitor_prev_epoch_sync_contribution_min_delay_seconds,
  "The min delay between when the validator should send the sync contribution and when it was received.", labels = ["validator"]
declareGauge validator_monitor_validator_in_current_sync_committee,
  "Is the validator in the current sync committee (1 for true and 0 for false)", labels = ["validator"]

declareGauge validator_monitor_validators_total,
  "Count of validators that are specifically monitored by this beacon node"
declareCounter validator_monitor_unaggregated_attestation_total,
  "Number of unaggregated attestations seen", labels = ["src", "validator"]
declareHistogram validator_monitor_unaggregated_attestation_delay_seconds,
  "The delay between when the validator should send the attestation and when it was received.", labels = ["src", "validator"]
declareCounter validator_monitor_sync_committee_messages_total,
  "Number of sync committee messages seen", labels = ["src", "validator"]
declareHistogram validator_monitor_sync_committee_messages_delay_seconds,
  "The delay between when the validator should send the sync committee message and when it was received.", labels = ["src", "validator"]
declareCounter validator_monitor_sync_contributions_total,
  "Number of sync contributions seen", labels = ["src", "validator"]
declareHistogram validator_monitor_sync_contributions_delay_seconds,
  "The delay between when the aggregator should send the sync contribution and when it was received.", labels = ["src", "validator"]
declareCounter validator_monitor_aggregated_attestation_total,
  "Number of aggregated attestations seen", labels = ["src", "validator"]
declareHistogram validator_monitor_aggregated_attestation_delay_seconds,
  "The delay between then the validator should send the aggregate and when it was received.", labels = ["src", "validator"]
declareCounter validator_monitor_attestation_in_aggregate_total,
  "Number of times an attestation has been seen in an aggregate", labels = ["src", "validator"]
declareCounter validator_monitor_sync_committee_message_in_contribution_total,
  "Number of times a sync committee message has been seen in a sync contribution", labels = ["src", "validator"]
declareHistogram validator_monitor_attestation_in_aggregate_delay_seconds,
  "The delay between when the validator should send the aggregate and when it was received.", labels = ["src", "validator"]
declareCounter validator_monitor_attestation_in_block_total,
  "Number of times an attestation has been seen in a block", labels = ["src", "validator"]
declareCounter validator_monitor_sync_committee_message_in_block_total,
  "Number of times a validator's sync committee message has been seen in a sync aggregate", labels = ["src", "validator"]
declareGauge validator_monitor_attestation_in_block_delay_slots,
  "The excess slots (beyond the minimum delay) between the attestation slot and the block slot.", labels = ["src", "validator"]
declareCounter validator_monitor_beacon_block_total,
  "Number of beacon blocks seen", labels = ["src", "validator"]
declareHistogram validator_monitor_beacon_block_delay_seconds,
  "The delay between when the validator should send the block and when it was received.", labels = ["src", "validator"]
declareCounter validator_monitor_exit_total,
  "Number of beacon exits seen", labels = ["src", "validator"]
declareCounter validator_monitor_proposer_slashing_total,
  "Number of proposer slashings seen", labels = ["src", "validator"]
declareCounter validator_monitor_attester_slashing_total,
  "Number of attester slashings seen", labels = ["src", "validator"]

type
  EpochSummary = object
    ## Similar to the state transition, we collect everything that happens in
    ## an epoch during that epoch and the one that follows it, then at the end
    ## of the monitoring period, we report the statistics to the user.
    ## In case of a deep reorg (>1 epoch) this information will be off, but will
    ## repair itself in the next epoch, which is a reasonable trade-off between
    ## correctness and utility.
    ##
    ## It should be noted that some metrics may be slightly inaccurate given the
    ## nature of gossip processing: in particular, old messages may reappear
    ## on the network and therefore be double-counted.
    attestations: int64
    attestation_min_delay: Option[Duration]
    attestation_aggregate_inclusions: int64
    attestation_block_inclusions: int64
    attestation_min_block_inclusion_distance: Option[uint64]

    aggregates: int64
    aggregate_min_delay: Option[Duration]

    sync_committee_messages: int64
    sync_committee_message_min_delay: Option[Duration]

    sync_signature_block_inclusions: int64
    sync_signature_contribution_inclusions: int64

    sync_contributions: int64
    sync_contribution_min_delay: Option[Duration]

    exits: int64
    proposer_slashings: int64
    attester_slashings: int64

  MonitoredValidator = object
    id: string # A short id is used above all for metrics
    pubkey: ValidatorPubKey
    index: Option[ValidatorIndex]
    summaries: array[2, EpochSummary] # We monitor the current and previous epochs

  ValidatorMonitor* = object
    epoch: Epoch # The most recent epoch seen in monitoring

    monitors: Table[ValidatorPubKey, ref MonitoredValidator]
    indices: Table[uint64, ref MonitoredValidator]

    knownValidators: int
    autoRegister: bool
    totals: bool

  MsgSource* {.pure.} = enum
    # From where a message is being sent - for compatibility with lighthouse, we
    # don't differentiate sync and requests, but rather use "gossip" - we also
    # don't differentiate in-beacon validators but use "api" as if they were
    # VC:s - this simplifies the initial implementation but should likely be
    # expanded in the future.
    gossip = "gossip"
    api = "api"

template toGaugeValue(v: bool): int64 =
  if v: 1 else: 0

proc update_if_lt[T](current: var Option[T], val: T) =
  if current.isNone() or val < current.get():
    current = some(val)

proc addMonitor*(
    self: var ValidatorMonitor, pubkey: ValidatorPubKey,
    index: Option[ValidatorIndex]) =
  if pubkey in self.monitors:
    return

  let id = shortLog(pubkey)
  let monitor = (ref MonitoredValidator)(id: id, index: index)

  self.monitors[pubkey] = monitor

  if index.isSome():
    self.indices[index.get().uint64] = monitor

template metricId: string =
  mixin self, id
  if self.totals: "total" else: id

proc addAutoMonitor*(
    self: var ValidatorMonitor, pubkey: ValidatorPubKey,
    index: ValidatorIndex) =
  if not self.autoRegister:
    return

  # automatic monitors must be registered with index - we don't look for them in
  # the state
  self.addMonitor(pubkey, some(index))

  info "Started monitoring validator",
    validator = shortLog(pubkey), pubkey, index

proc init*(T: type ValidatorMonitor, autoRegister = false, totals = false): T =
  T(autoRegister: autoRegister, totals: totals)

template summaryIdx(epoch: Epoch): int = (epoch.uint64 mod 2).int

template withEpochSummary(
  self: var ValidatorMonitor, monitor: var MonitoredValidator,
  epochParam: Epoch, body: untyped) =
  let epoch = epochParam
  if epoch == self.epoch or epoch + 1 == self.epoch:
    template epochSummary: untyped {.inject.} = monitor.summaries[summaryIdx(epoch)]
    body

proc updateEpoch(self: var ValidatorMonitor, epoch: Epoch) =
  # Called at the start of a new epoch to provide a summary of the events 2
  # epochs back then clear the slate for new reporting.
  if epoch <= self.epoch:
    return

  let
    clearMonitor = epoch > self.epoch + 1
    # index of the EpochSummary that we'll first report, then clear
    summaryIdx = epoch.summaryIdx

  if clearMonitor:
    # More than one epoch passed since the last check which makes it difficult
    # to report correctly with the amount of data we store - skip this round
    # and hope things improve
    notice "Resetting validator monitoring", epoch, monitorEpoch = self.epoch

  self.epoch = epoch

  validator_monitor_validators_total.set(self.monitors.len().int64)

  for (_, monitor) in self.monitors.mpairs():
    if clearMonitor:
      monitor.summaries = default(type(monitor.summaries))
      continue

    let
      id = monitor.id

    let summary = monitor.summaries[summaryIdx]

    validator_monitor_prev_epoch_attestations_total.set(
      summary.attestations, [metricId])

    if summary.attestation_min_delay.isSome():
      validator_monitor_prev_epoch_attestations_min_delay_seconds.observe(
        summary.attestation_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_attestation_aggregate_inclusions.set(
      summary.attestation_aggregate_inclusions, [metricId])
    validator_monitor_prev_epoch_attestation_block_inclusions.set(
      summary.attestation_block_inclusions, [metricId])

    if summary.attestation_min_block_inclusion_distance.isSome():
      validator_monitor_prev_epoch_attestation_block_min_inclusion_distance.set(
        summary.attestation_min_block_inclusion_distance.get().int64, [metricId])

    validator_monitor_prev_epoch_sync_committee_messages_total.set(
      summary.sync_committee_messages, [metricId])

    if summary.sync_committee_message_min_delay.isSome():
      validator_monitor_prev_epoch_sync_committee_messages_min_delay_seconds.observe(
        summary.sync_committee_message_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_sync_contribution_inclusions.set(
      summary.sync_signature_contribution_inclusions, [metricId])
    validator_monitor_prev_epoch_sync_signature_block_inclusions.set(
      summary.sync_signature_block_inclusions, [metricId])

    validator_monitor_prev_epoch_sync_contributions_total.set(
      summary.sync_contributions, [metricId])
    if summary.sync_contribution_min_delay.isSome():
      validator_monitor_prev_epoch_sync_contribution_min_delay_seconds.observe(
        summary.sync_contribution_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_aggregates_total.set(
        summary.aggregates, [metricId])

    if summary.aggregate_min_delay.isSome():
      validator_monitor_prev_epoch_aggregates_min_delay_seconds.observe(
        summary.aggregate_min_delay.get().toFloatSeconds(), [metricId])

    validator_monitor_prev_epoch_exits_total.set(
      summary.exits, [metricId])

    validator_monitor_prev_epoch_proposer_slashings_total.set(
        summary.proposer_slashings, [metricId])

    validator_monitor_prev_epoch_attester_slashings_total.set(
      summary.attester_slashings, [metricId])

    monitor.summaries[summaryIdx] = default(type(monitor.summaries[summaryIdx]))

func is_active_unslashed_in_previous_epoch(status: RewardStatus): bool =
  let flags = status.flags
  RewardFlags.isActiveInPreviousEpoch in flags and
    RewardFlags.isSlashed notin flags

func is_previous_epoch_source_attester(status: RewardStatus): bool =
  status.is_previous_epoch_attester.isSome()

func is_previous_epoch_head_attester(status: RewardStatus): bool =
  RewardFlags.isPreviousEpochHeadAttester in status.flags

func is_previous_epoch_target_attester(status: RewardStatus): bool =
  RewardFlags.isPreviousEpochTargetAttester in status.flags

func is_previous_epoch_source_attester(status: ParticipationInfo): bool =
  ParticipationFlag.timelySourceAttester in status.flags

func is_previous_epoch_head_attester(status: ParticipationInfo): bool =
  ParticipationFlag.timelyHeadAttester in status.flags

func is_previous_epoch_target_attester(status: ParticipationInfo): bool =
  ParticipationFlag.timelyTargetAttester in status.flags

func is_active_unslashed_in_previous_epoch(status: ParticipationInfo): bool =
  ParticipationFlag.eligible in status.flags

proc registerEpochInfo*(
    self: var ValidatorMonitor, epoch: Epoch, info: ForkedEpochInfo,
    state: ForkyBeaconState) =
  # Register rewards, as computed during the epoch transition that lands in
  # `epoch` - the rewards will be from attestations that were created at
  # `epoch - 2`.

  if epoch < 2 or self.monitors.len == 0:
    return

  withEpochInfo(info):
    for pubkey, monitor in self.monitors:
      if monitor.index.isNone:
        continue

      let
        idx = monitor.index.get()

      if info.validators.lenu64 <= idx.uint64:
        # No summary for this validator (yet?)
        debug "No reward information for validator",
          id = monitor.id, idx
        continue

      let
        prev_epoch = epoch - 2
        id = monitor.id

      let status = info.validators[idx]

      if not status.is_active_unslashed_in_previous_epoch():
        # Monitored validator is not active, due to awaiting activation
        # or being exited/withdrawn. Do not attempt to report on its
        # attestations.
        continue

      let
        previous_epoch_matched_source = status.is_previous_epoch_source_attester()
        previous_epoch_matched_target = status.is_previous_epoch_target_attester()
        previous_epoch_matched_head = status.is_previous_epoch_head_attester()

      # Indicates if any attestation made it on-chain.
      # For Base states, this will be *any* attestation whatsoever. For Altair states,
      # this will be any attestation that matched a "timely" flag.
      if previous_epoch_matched_source:
        # These two metrics are the same - keep both around for LH compatibility
        validator_monitor_prev_epoch_on_chain_attester_hit.inc(1, [metricId])
        validator_monitor_prev_epoch_on_chain_source_attester_hit.inc(1, [metricId])

        info "Previous epoch attestation included",
          timely_source = previous_epoch_matched_source,
          timely_target = previous_epoch_matched_target,
          timely_head = previous_epoch_matched_head,
          epoch = prev_epoch,
          validator = id
      else:
        validator_monitor_prev_epoch_on_chain_attester_miss.inc(1, [metricId])
        validator_monitor_prev_epoch_on_chain_source_attester_miss.inc(1, [metricId])

        warn "Previous epoch attestation missing",
          epoch = prev_epoch,
          validator = id

      # Indicates if any on-chain attestation hit the head.
      if previous_epoch_matched_head:
        validator_monitor_prev_epoch_on_chain_head_attester_hit.inc(1, [metricId])
      else:
        validator_monitor_prev_epoch_on_chain_head_attester_miss.inc(1, [metricId])
        notice "Attestation failed to match head",
          epoch = prev_epoch,
          validator = id

      # Indicates if any on-chain attestation hit the target.
      if previous_epoch_matched_target:
        validator_monitor_prev_epoch_on_chain_target_attester_hit.inc(1, [metricId])
      else:
        validator_monitor_prev_epoch_on_chain_target_attester_miss.inc(1, [metricId])

        notice "Attestation failed to match target",
          epoch = prev_epoch,
          validator = id

      when state isnot phase0.BeaconState: # altair+
        # Indicates the number of sync committee signatures that made it into
        # a sync aggregate in the current_epoch (state.epoch - 1).
        # Note: Unlike attestations, sync committee signatures must be included in the
        # immediate next slot. Hence, num included sync aggregates for `state.epoch - 1`
        # is available right after state transition to state.epoch.
        let current_epoch = epoch - 1

        if state.current_sync_committee.pubkeys.data.contains(pubkey):
          validator_monitor_validator_in_current_sync_committee.set(1, [metricId])

          self.withEpochSummary(monitor[], current_epoch):
            info "Current epoch sync signatures",
              included = epochSummary.sync_signature_block_inclusions,
              expected = SLOTS_PER_EPOCH,
              epoch = current_epoch,
              validator = id
        else:
          validator_monitor_validator_in_current_sync_committee.set(0, [metricId])
          debug "Validator isn't part of the current sync committee",
            epoch = current_epoch,
            validator = id

  self.updateEpoch(epoch)

proc registerState*(self: var ValidatorMonitor, state: ForkyBeaconState) =
  # Update indices for the validators we're monitoring
  for v in self.knownValidators..<state.validators.len:
    self.monitors.withValue(state.validators[v].pubkey, monitor):
      monitor[][].index = some(ValidatorIndex(v))
      self.indices[uint64(v)] = monitor[]

      info "Started monitoring validator",
        validator = monitor[][].id, pubkey = state.validators[v].pubkey, index = v

  self.knownValidators = state.validators.len

  let
    current_epoch = state.slot.epoch

  # Update metrics for monitored validators according to the latest rewards
  for (_, monitor) in self.monitors.mpairs():
    if not monitor[].index.isSome():
      continue

    let idx = monitor[].index.get()
    if state.balances.lenu64 <= idx.uint64:
      continue

    let id = monitor[].id
    validator_monitor_balance_gwei.set(
      state.balances[idx].toGaugeValue(), [metricId])
    validator_monitor_effective_balance_gwei.set(
      state.validators[idx].effective_balance.toGaugeValue(), [metricId])
    validator_monitor_slashed.set(
      state.validators[idx].slashed.toGaugeValue(), [metricId])
    validator_monitor_active.set(
      is_active_validator(state.validators[idx], current_epoch).toGaugeValue(), [metricId])
    validator_monitor_exited.set(
      is_exited_validator(state.validators[idx], current_epoch).toGaugeValue(), [metricId])
    validator_monitor_withdrawable.set(
      is_withdrawable_validator(state.validators[idx], current_epoch).toGaugeValue(), [metricId])
    validator_activation_eligibility_epoch.set(
      state.validators[idx].activation_eligibility_epoch.toGaugeValue(), [metricId])
    validator_activation_epoch.set(
      state.validators[idx].activation_epoch.toGaugeValue(), [metricId])
    validator_exit_epoch.set(
      state.validators[idx].exit_epoch.toGaugeValue(), [metricId])
    validator_withdrawable_epoch.set(
      state.validators[idx].withdrawable_epoch.toGaugeValue(), [metricId])

template withMonitor(self: var ValidatorMonitor, key: ValidatorPubKey, body: untyped): untyped =
  self.monitors.withValue(key, valuex):
    template monitor: untyped {.inject.} = valuex[][]
    body

template withMonitor(self: var ValidatorMonitor, idx: uint64, body: untyped): untyped =
  self.indices.withValue(idx, valuex):
    template monitor: untyped {.inject.} = valuex[][]
    body

template withMonitor(self: var ValidatorMonitor, idx: ValidatorIndex, body: untyped): untyped =
  withMonitor(self, idx.uint64, body)

proc delay(slot: Slot, time: BeaconTime, offset: Duration): Duration =
  time - slot.toBeaconTime(offset)

proc registerAttestation*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    attestation: Attestation,
    idx: ValidatorIndex) =
  let
    slot = attestation.data.slot
    delay = delay(slot, seen_timestamp, attestationSlotOffset)

  self.withMonitor(idx):
    let id = monitor.id
    validator_monitor_unaggregated_attestation_total.inc(1, [$src, metricId])
    validator_monitor_unaggregated_attestation_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Attestation seen",
      attestation = shortLog(attestation),
      src, epoch = slot.epoch, validator = id

    self.withEpochSummary(monitor, slot.epoch):
      epochSummary.attestations += 1
      update_if_lt(epochSummary.attestation_min_delay, delay)

proc registerAggregate*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    signed_aggregate_and_proof: SignedAggregateAndProof,
    attesting_indices: openArray[ValidatorIndex]) =
  let
    slot = signed_aggregate_and_proof.message.aggregate.data.slot
    delay = delay(slot, seen_timestamp, aggregateSlotOffset)
    aggregator_index = signed_aggregate_and_proof.message.aggregator_index

  self.withMonitor(aggregator_index):
    let id = monitor.id
    validator_monitor_aggregated_attestation_total.inc(1, [$src, metricId])
    validator_monitor_aggregated_attestation_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Aggregated attestion seen",
      aggregate = shortLog(signed_aggregate_and_proof.message.aggregate),
      src, epoch = slot.epoch, validator = id

    self.withEpochSummary(monitor, slot.epoch):
      epochSummary.aggregates += 1
      update_if_lt(epochSummary.aggregate_min_delay, delay)

  for idx in attesting_indices:
    self.withMonitor(idx):
      let id = monitor.id
      validator_monitor_attestation_in_aggregate_total.inc(1, [$src, metricId])
      validator_monitor_attestation_in_aggregate_delay_seconds.observe(
        delay.toFloatSeconds(), [$src, metricId])

      info "Attestation included in aggregate",
        aggregate = shortLog(signed_aggregate_and_proof.message.aggregate),
        src, epoch = slot.epoch, validator = id

      self.withEpochSummary(monitor, slot.epoch):
        epochSummary.attestation_aggregate_inclusions += 1

proc registerAttestationInBlock*(
    self: var ValidatorMonitor,
    data: AttestationData,
    attesting_index: ValidatorIndex,
    blck: auto) =
  self.withMonitor(attesting_index):
    let
      id = monitor.id
      inclusion_lag = (blck.slot - data.slot) - MIN_ATTESTATION_INCLUSION_DELAY
      epoch = data.slot.epoch

    validator_monitor_attestation_in_block_total.inc(1, ["block", id])
    validator_monitor_attestation_in_block_delay_slots.set(inclusion_lag.int64, ["block", id])

    info "Attestation included in block",
      attestation_data = shortLog(data),
      block_slot = blck.slot,
      inclusion_lag_slots = inclusion_lag,
      epoch = epoch, validator = id

    self.withEpochSummary(monitor, epoch):
      epochSummary.attestation_block_inclusions += 1
      update_if_lt(
        epochSummary.attestation_min_block_inclusion_distance, inclusion_lag)

proc registerBeaconBlock*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    blck: auto) =
  self.withMonitor(blck.proposer_index):
    let
      id = monitor.id
      slot = blck.slot
      delay = delay(slot, seen_timestamp, seconds(0))

    validator_monitor_beacon_block_total.inc(1, [$src, metricId])
    validator_monitor_beacon_block_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Block seen",
      blck = shortLog(blck), src, epoch = slot.epoch, validator = id

proc registerSyncCommitteeMessage*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    sync_committee_message: SyncCommitteeMessage) =
  self.withMonitor(sync_committee_message.validator_index):
    let
      id = monitor.id
      slot = sync_committee_message.slot
      delay = delay(slot, seen_timestamp, syncCommitteeMessageSlotOffset)

    validator_monitor_sync_committee_messages_total.inc(1, [$src, metricId])
    validator_monitor_sync_committee_messages_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Sync committee message seen",
      syncCommitteeMessage = shortLog(sync_committee_message.beacon_block_root),
      src, epoch = slot.epoch, validator = id

    self.withEpochSummary(monitor, slot.epoch):
      epochSummary.sync_committee_messages += 1
      update_if_lt(epochSummary.sync_committee_message_min_delay, delay)

proc registerSyncContribution*(
    self: var ValidatorMonitor,
    src: MsgSource,
    seen_timestamp: BeaconTime,
    sync_contribution: SignedContributionAndProof,
    participants: openArray[ValidatorIndex]) =
  let
    slot = sync_contribution.message.contribution.slot
    beacon_block_root = sync_contribution.message.contribution.beacon_block_root
    delay = delay(slot, seen_timestamp, syncContributionSlotOffset)

  let aggregator_index = sync_contribution.message.aggregator_index
  self.withMonitor(aggregator_index):
    let id = monitor.id
    validator_monitor_sync_contributions_total.inc(1, [$src, metricId])
    validator_monitor_sync_contributions_delay_seconds.observe(
      delay.toFloatSeconds(), [$src, metricId])

    info "Sync contribution seen",
      contribution = shortLog(sync_contribution.message.contribution),
      src, epoch = slot.epoch, validator = id

    self.withEpochSummary(monitor, slot.epoch):
      epochSummary.sync_contributions += 1
      update_if_lt(epochSummary.sync_contribution_min_delay, delay)

  for participant in participants:
    self.withMonitor(participant):
      let id = monitor.id
      validator_monitor_sync_committee_message_in_contribution_total.inc(1, [$src, metricId])

      info "Sync signature included in contribution",
        contribution = shortLog(sync_contribution.message.contribution),
        src, epoch = slot.epoch, validator = id

      self.withEpochSummary(monitor, slot.epoch):
        epochSummary.sync_signature_contribution_inclusions += 1

proc registerSyncAggregateInBlock*(
    self: var ValidatorMonitor, slot: Slot, beacon_block_root: Eth2Digest,
    pubkey: ValidatorPubKey) =
  self.withMonitor(pubkey):
    let id = monitor.id
    validator_monitor_sync_committee_message_in_block_total.inc(1, ["block", id])

    info "Sync signature included in block",
      head = beacon_block_root, slot = slot, validator = id

    self.withEpochSummary(monitor, slot.epoch):
      epochSummary.sync_signature_block_inclusions += 1

proc registerVoluntaryExit*(
  self: var ValidatorMonitor, src: MsgSource, exit: VoluntaryExit) =
  self.withMonitor(exit.validator_index.ValidatorIndex):
    let
      id = monitor.id
      epoch = exit.epoch

    validator_monitor_exit_total.inc(1, [$src, metricId])

    notice "Voluntary exit seen",
      epoch = epoch, validator = id, src = src

    self.withEpochSummary(monitor, epoch):
      epochSummary.exits += 1

proc registerProposerSlashing*(
  self: var ValidatorMonitor, src: MsgSource, slashing: ProposerSlashing) =
  let proposer = slashing.signed_header_1.message.proposer_index

  self.withMonitor(proposer):
    let
      id = monitor.id
      slot = slashing.signed_header_1.message.slot
      root_1 = hash_tree_root(slashing.signed_header_1.message)
      root_2 = hash_tree_root(slashing.signed_header_2.message)

    validator_monitor_proposer_slashing_total.inc(1, [$src, metricId])

    warn "Proposer slashing seen",
      root_2 = root_2, root_1 = root_1, slot = slot, validator = id, src = src

    self.withEpochSummary(monitor, slot.epoch):
      epochSummary.proposer_slashings += 1

proc registerAttesterSlashing*(
    self: var ValidatorMonitor, src: MsgSource, slashing: AttesterSlashing) =
  let data = slashing.attestation_1.data

  for idx in slashing.attestation_2.attesting_indices:
    if idx notin slashing.attestation_1.attesting_indices.asSeq:
      continue

    self.withMonitor(idx):
      let
        id = monitor.id
        slot = data.slot

      validator_monitor_attester_slashing_total.inc(1, [$src, metricId])

      warn "Attester slashing seen",
        slot = slot, validator = id, src = src

      self.withEpochSummary(monitor, slot.epoch):
        epochSummary.attester_slashings += 1
