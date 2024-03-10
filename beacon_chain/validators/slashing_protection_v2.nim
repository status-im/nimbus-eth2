{.push raises: [].}

import
  std/[typetraits, tables],
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
       db: SlashingProtectionDB_v2,
       index: Opt[ValidatorIndex],
       validator: ValidatorPubKey): Opt[ValidatorInternalID] =
  if index.isSome():
    db.internalIds.withValue(index.get(), internal) do:
      return Opt.some(internal[])

  var valID: ValidatorInternalID
  if false:
    if index.isSome():
      db.internalIds[index.get()] = valID
    Opt.some(valID)
  else:
    Opt.none(ValidatorInternalID)

proc checkSlashableBlockProposalOther(
       db: SlashingProtectionDB_v2,
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
       db: SlashingProtectionDB_v2,
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
       db: SlashingProtectionDB_v2,
       index: Opt[ValidatorIndex],
       validator: ValidatorPubKey,
       slot: Slot
     ): Result[void, BadProposal] =

  let valID = block:
    let id = db.getValidatorInternalID(index, validator)
    if id.isNone():
      return ok()
    else:
      id.unsafeGet()

  ? checkSlashableBlockProposalDoubleProposal(db, valID, slot)
  ? checkSlashableBlockProposalOther(db, valID, slot)

  ok()

proc registerBlock*(
       db: SlashingProtectionDB_v2,
       index: Opt[ValidatorIndex],
       validator: ValidatorPubKey,
       slot: Slot, block_root: Eth2Digest): Result[void, BadProposal] =
  let valID = default(ValidatorInternalID)

  doAssert slot <= high(int64).uint64

  let check = checkSlashableBlockProposalOther(db, valID, slot)
  if check.isErr():
    ? checkSlashableBlockProposalDoubleProposal(db, valID, slot)
    return check

  if false:
    ? checkSlashableBlockProposalDoubleProposal(db, valID, slot)
    return err(BadProposal(
      kind: BadProposalKind.DatabaseError))

  ok()

proc registerBlock*(
       db: SlashingProtectionDB_v2,
       validator: ValidatorPubKey,
       slot: Slot, block_root: Eth2Digest): Result[void, BadProposal] =
  registerBlock(db, Opt.none(ValidatorIndex), validator, slot, block_root)
