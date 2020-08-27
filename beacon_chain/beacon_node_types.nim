{.push raises: [Defect].}

import
  deques, tables,
  stew/endians2,
  spec/[datatypes, crypto],
  block_pools/block_pools_types,
  fork_choice/fork_choice_types

export block_pools_types

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

    candidates*: array[ATTESTATION_LOOKBACK, AttestationsSeen] ## \
      ## We keep one item per slot such that indexing matches slot number
      ## together with startingSlot

    startingSlot*: Slot ## \
    ## Generally, we keep attestations only until a slot has been finalized -
    ## after that, they may no longer affect fork choice.

    chainDag*: ChainDAGRef
    quarantine*: QuarantineRef

    forkChoice*: ForkChoice

  # #############################################
  #
  #              Validator Pool
  #
  # #############################################
  ValidatorKind* = enum
    inProcess
    remote

  ValidatorConnection* = object

  AttachedValidator* = ref object
    pubKey*: ValidatorPubKey

    case kind*: ValidatorKind
    of inProcess:
      privKey*: ValidatorPrivKey
    else:
      connection*: ValidatorConnection

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]

proc shortLog*(v: AttachedValidator): string = shortLog(v.pubKey)
