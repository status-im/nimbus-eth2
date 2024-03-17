{.push raises: [].}

import
  std/tables,
  results,
  ../spec/datatypes/base,
  ../spec/helpers,
  ./slashing_protection_common

type
  SlashingProtectionDB_v2* = ref object
    internalIds: Table[ValidatorIndex, ValidatorInternalID]

  ValidatorInternalID = int64

proc init*(T: type SlashingProtectionDB_v2,
           genesis_validators_root: Eth2Digest,
           databasePath: string,
           databaseName: string): T = default(T)

proc getValidatorInternalID(
       index: Opt[ValidatorIndex],
       validator: ValidatorPubKey): Opt[ValidatorInternalID] =
  var valID: ValidatorInternalID
  if false:
    Opt.some(valID)
  else:
    Opt.none(ValidatorInternalID)

proc checkSlashableBlockProposalOther(
       valID: ValidatorInternalID,
       slot: Slot
     ): Result[void, BadProposal] =

  block:
    var minSlot: int64
    if false:
      # 6 second (minimal preset) slots => overflow at ~1.75 trillion years
      # under minimal preset, and twice that under mainnet preset
      doAssert slot <= high(int64).uint64

      if int64(slot) <= minSlot:
        return err(BadProposal(
          kind: MinSlotViolation,
          minSlot: Slot minSlot,
          candidateSlot: slot
        ))

  ok()

proc checkSlashableBlockProposalDoubleProposal(
       valID: ValidatorInternalID,
       slot: Slot
     ): Result[void, BadProposal] =

  block:
    var root: Eth2Digest
    if false:
      # Conflicting block exist
      return err(BadProposal(
        kind: DoubleProposal,
        existing_block: root))

  ok()

proc checkSlashableBlockProposal*(
       index: Opt[ValidatorIndex],
       validator: ValidatorPubKey,
       slot: Slot
     ): Result[void, BadProposal] =

  let valID = block:
    let id = getValidatorInternalID(index, validator)
    if id.isNone():
      return ok()
    else:
      id.unsafeGet()

  ? checkSlashableBlockProposalDoubleProposal(valID, slot)
  ? checkSlashableBlockProposalOther(valID, slot)

  ok()

proc registerBlock*(
       index: Opt[ValidatorIndex],
       validator: ValidatorPubKey,
       slot: Slot, block_root: Eth2Digest): Result[void, BadProposal] =
  let valID = default(ValidatorInternalID)

  doAssert slot <= high(int64).uint64

  let check = checkSlashableBlockProposalOther(valID, slot)
  if check.isErr():
    ? checkSlashableBlockProposalDoubleProposal(valID, slot)
    return check

  if false:
    ? checkSlashableBlockProposalDoubleProposal(valID, slot)
    return err(BadProposal(
      kind: BadProposalKind.DatabaseError))

  ok()

proc registerBlock*(
       validator: ValidatorPubKey,
       slot: Slot, block_root: Eth2Digest): Result[void, BadProposal] =
  registerBlock(Opt.none(ValidatorIndex), validator, slot, block_root)
