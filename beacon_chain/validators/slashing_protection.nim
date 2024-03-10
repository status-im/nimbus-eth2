import
  results,
  ../spec/datatypes/base,
  ./slashing_protection_common,
  ./slashing_protection_v2

export slashing_protection_common

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
