import
  results,
  ../spec/datatypes/base,
  ./slashing_protection_common

type
  SlashingProtectionDB_v2 = ref object
  ValidatorInternalID = int64

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

proc registerBlock(
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

type
  SlashingProtectionDB = ref object
    db_v2: SlashingProtectionDB_v2

proc loadUnchecked(
       T: type SlashingProtectionDB,
       basePath, dbname: string, readOnly: bool
     ): SlashingProtectionDB {.raises:[IOError].}=
  new result

  result.modes = {}
  try:
    result.db_v2 = SlashingProtectionDB_v2.loadUnchecked(
      basePath, dbname, readOnly
    )
  except CatchableError as err:
    quit 1

proc registerBlock*(
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       slot: Slot, block_signing_root: Eth2Digest): Result[void, BadProposal] =
  registerBlock(Opt.some(index), validator, slot, block_signing_root)
