{.push raises: [Defect].}

import
  std/[deques, sets, streams, tables],
  stew/endians2,
  spec/[datatypes, digest, crypto],
  block_pools/block_pools_types,
  fork_choice/fork_choice_types,
  validator_slashing_protection

from libp2p/protocols/pubsub/pubsub import ValidationResult

export block_pools_types, ValidationResult

const
  ATTESTATION_LOOKBACK* =
    min(4'u64, SLOTS_PER_EPOCH) + MIN_ATTESTATION_INCLUSION_DELAY
    ## The number of slots we'll keep track of in terms of "free" attestations
    ## that potentially could be added to a newly created block

type
  # #############################################
  #
  #             Attestation Pool
  #
  # #############################################
  Validation* = object
    ## Validations collect a set of signatures for a distict attestation - in
    ## eth2, a single bit is used to keep track of which signatures have been
    ## added to the aggregate meaning that only non-overlapping aggregates may
    ## be further combined.
    aggregation_bits*: CommitteeValidatorsBits
    aggregate_signature*: ValidatorSig

  AttestationEntry* = object
    ## Each entry holds the known signatures for a particular, distinct vote
    data*: AttestationData
    blck*: BlockRef
    validations*: seq[Validation]

  AttestationsSeen* = object
    attestations*: seq[AttestationEntry] ## \
    ## Depending on the world view of the various validators, they may have
    ## voted on different states - here we collect all the different
    ## combinations that validators have come up with so that later, we can
    ## count how popular each world view is (fork choice)
    ## TODO this could be a Table[AttestationData, seq[Validation] or something
    ##      less naive

  AttestationPool* = object
    ## The attestation pool keeps track of all attestations that potentially
    ## could be added to a block during block production.
    ## These attestations also contribute to the fork choice, which combines
    ## "free" attestations with those found in past blocks - these votes
    ## are tracked separately in the fork choice.

    attestationAggregates*: Table[Slot, Table[Eth2Digest, Attestation]]
      ## An up-to-date aggregate of each (htr-ed) attestation_data we see for
      ## each slot. We keep aggregates up to 32 slots back from the current slot.

    candidates*: array[ATTESTATION_LOOKBACK, AttestationsSeen] ## \
      ## We keep one item per slot such that indexing matches slot number
      ## together with startingSlot

    startingSlot*: Slot ## \
    ## Generally, we keep attestations only until a slot has been finalized -
    ## after that, they may no longer affect fork choice.

    chainDag*: ChainDAGRef
    quarantine*: QuarantineRef

    forkChoice*: ForkChoice

    lastVotedEpoch*: seq[Option[Epoch]] # Sequence based on validator indices

  ExitPool* = object
    ## The exit pool tracks attester slashings, proposer slashings, and
    ## voluntary exits that could be added to a proposed block.

    attester_slashings*: Deque[AttesterSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    proposer_slashings*: Deque[ProposerSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    voluntary_exits*: Deque[SignedVoluntaryExit]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    prior_seen_attester_slashed_indices*: HashSet[uint64] ##\
    ## Records attester-slashed indices seen.

    prior_seen_proposer_slashed_indices*: HashSet[uint64] ##\
    ## Records proposer-slashed indices seen.

    prior_seen_voluntary_exit_indices*: HashSet[uint64] ##\
    ## Records voluntary exit indices seen.

    chainDag*: ChainDAGRef
    quarantine*: QuarantineRef

  # #############################################
  #
  #              Validator Pool
  #
  # #############################################
  ValidatorKind* = enum
    inProcess
    remote

  ValidatorConnection* = object
    inStream*: Stream
    outStream*: Stream
    pubKeyStr*: string

  AttachedValidator* = ref object
    pubKey*: ValidatorPubKey

    case kind*: ValidatorKind
    of inProcess:
      privKey*: ValidatorPrivKey
    else:
      connection*: ValidatorConnection

    # The index at which this validator has been observed in the chain -
    # it does not change as long as there are no reorgs on eth1 - however, the
    # index might not be valid in all eth2 histories, so it should not be
    # assumed that a valid index is stored here!
    index*: Option[ValidatorIndex]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB

func shortLog*(v: AttachedValidator): string = shortLog(v.pubKey)
