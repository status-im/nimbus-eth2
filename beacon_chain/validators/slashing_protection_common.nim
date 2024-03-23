import ../consensus_object_pools/block_dag

type
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
      message: string
