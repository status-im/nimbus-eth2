{.push raises: [Defect].}

import
  deques, tables,
  stew/endians2,
  spec/[datatypes, crypto, digest],
  block_pools/block_pools_types,
  block_pool, # TODO: refactoring compat shim
  fork_choice/fork_choice_types

export block_pools_types

type
  # #############################################
  #
  #             Attestation Pool
  #
  # #############################################
  Validation* = object
    aggregation_bits*: CommitteeValidatorsBits
    aggregate_signature*: ValidatorSig

  # Per Danny as of 2018-12-21:
  # Yeah, you can do any linear combination of signatures. but you have to
  # remember the linear combination of pubkeys that constructed
  # if you have two instances of a signature from pubkey p, then you need 2*p
  # in the group pubkey because the attestation bitlist is only 1 bit per
  # pubkey right now, attestations do not support this it could be extended to
  # support N overlaps up to N times per pubkey if we had N bits per validator
  # instead of 1
  # We are shying away from this for the time being. If there end up being
  # substantial difficulties in network layer aggregation, then adding bits to
  # aid in supporting overlaps is one potential solution

  AttestationEntry* = object
    data*: AttestationData
    blck*: BlockRef
    validations*: seq[Validation] ## \
    ## Instead of aggregating the signatures eagerly, we simply dump them in
    ## this seq and aggregate only when needed
    ## TODO there are obvious caching opportunities here..

  AttestationsSeen* = object
    attestations*: seq[AttestationEntry] ## \
    ## Depending on the world view of the various validators, they may have
    ## voted on different states - here we collect all the different
    ## combinations that validators have come up with so that later, we can
    ## count how popular each world view is (fork choice)
    ## TODO this could be a Table[AttestationData, seq[Validation] or something
    ##      less naive

  UnresolvedAttestation* = object
    attestation*: Attestation
    tries*: int

  AttestationPool* = object
    ## The attestation pool keeps all attestations that are known to the
    ## client - each attestation counts as votes towards the fork choice
    ## rule that determines which block we consider to be the head. The pool
    ## contains both votes that have been included in the chain and those that
    ## have not.

    mapSlotsToAttestations*: Deque[AttestationsSeen] ## \
    ## We keep one item per slot such that indexing matches slot number
    ## together with startingSlot

    startingSlot*: Slot ## \
    ## Generally, we keep attestations only until a slot has been finalized -
    ## after that, they may no longer affect fork choice.

    blockPool*: BlockPool

    unresolved*: Table[Eth2Digest, UnresolvedAttestation]

    forkChoice*: ForkChoice ##\
    ## Tracks the most recent vote of each attester

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
