import
  serialization,
  ../spec/digest

type
  SPDIR* = object
    ## Slashing Protection Database Interchange Format
    metadata*: SPDIR_Meta
    data*: seq[SPDIR_Validator]

  Eth2Digest0x* = distinct Eth2Digest
    ## The spec mandates "0x" prefix on serialization
    ## So we need to set custom read/write

  PubKeyBytes* = array[48, byte]
    ## This is the serialized byte representation
    ## of a Validator Public Key.
    ## Portable between backend implementations
    ## and limits serialization/deserialization call

  PubKey0x* = distinct PubKeyBytes
    ## The spec mandates "0x" prefix on serialization
    ## So we need to set custom read/write
    ## We also assume that pubkeys in the database
    ## are valid points on the BLS12-381 G1 curve
    ## (so we skip fromRaw/serialization checks)

  EpochString* = distinct uint64
    ## The spec mandates string serialization for wide compatibility (javascript)

  SPDIR_Meta* = object
    interchange_format_version*: string
    genesis_validators_root*: Eth2Digest0x

  SPDIR_Validator* = object
    pubkey*: PubKey0x
    signed_blocks*: seq[SPDIR_SignedBlock]
    signed_attestations*: seq[SPDIR_SignedAttestation]

  SPDIR_SignedBlock* = object
    slot*: EpochString
    signing_root*: Option[Eth2Digest0x] # compute_signing_root(block, domain)

  SPDIR_SignedAttestation* = object
    source_epoch*: EpochString
    target_epoch*: EpochString
    signing_root*: Option[Eth2Digest0x] # compute_signing_root(attestation, domain)

# Slashing Protection types
# --------------------------------------------

  SlashingImportStatus* = enum
    siSuccess
    siFailure
    siPartial

  BadVoteKind* = enum
    ## Attestation bad vote kind
    # h: height (i.e. epoch for attestation, slot for blocks)
    # t: target
    # s: source
    # 1: existing attestations
    # 2: candidate attestation

    # Spec slashing condition
    DoubleVote   # h(t1) == h(t2)
    SurroundVote # h(s1) < h(s2) < h(t2) < h(t1) or h(s2) < h(s1) < h(t1) < h(t2)

    # Non-spec, should never happen in a well functioning client
    TargetPrecedesSource # h(t1) < h(s1) - current epoch precedes last justified epoch

    # EIP-3067 (https://eips.ethereum.org/EIPS/eip-3076)
    MinSourceViolation   # h(s2) < h(s1) - EIP3067 condition 4 (strict inequality)
    MinTargetViolation   # h(t2) <= h(t1) - EIP3067 condition 5
    DatabaseError          # Cannot read/write the slashing protection db

  BadVote* {.pure.} = object
    case kind*: BadVoteKind
    of DoubleVote:
      existingAttestation*: Eth2Digest
    of SurroundVote:
      existingAttestationRoot*: Eth2Digest # Many roots might be in conflict
      sourceExisting*, targetExisting*: uint64
      sourceSlashable*, targetSlashable*: uint64
    of TargetPrecedesSource:
      discard
    of MinSourceViolation:
      minSource*: uint64
      candidateSource*: uint64
    of MinTargetViolation:
      minTarget*: uint64
      candidateTarget*: uint64
    of BadVoteKind.DatabaseError:
      message*: string

  BadProposalKind* {.pure.} = enum
    # Spec slashing condition
    DoubleProposal         # h(t1) == h(t2)
    # EIP-3067 (https://eips.ethereum.org/EIPS/eip-3076)
    MinSlotViolation       # h(t2) <= h(t1)
    DatabaseError          # Cannot read/write the slashing protection db

  BadProposal* = object
    case kind*: BadProposalKind
    of DoubleProposal:
      existingBlock*: Eth2Digest
    of MinSlotViolation:
      minSlot*: uint64
      candidateSlot*: uint64
    of BadProposalKind.DatabaseError:
      message*: string
