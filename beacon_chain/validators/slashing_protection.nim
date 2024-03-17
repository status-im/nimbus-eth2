{.push raises: [].}

import
  std/os,
  results,
  stew/byteutils,
  chronicles/timings,
  ../spec/datatypes/base,
  ./slashing_protection_common,
  ./slashing_protection_v2

export slashing_protection_common

type
  SlashProtDBMode = enum
    kCompleteArchive # Complete Format V2 backend (saves all attestations)
    kLowWatermark    # Low-Watermark Format V2 backend (prunes attestations)

  SlashingProtectionDB = ref object
    ## Database storing the blocks attested
    ## by validators attached to a beacon node
    ## or validator client.
    db_v2: SlashingProtectionDB_v2
    modes: set[SlashProtDBMode]


func version(_: type SlashingProtectionDB): static int =
  2


proc init(
       T: type SlashingProtectionDB,
       genesis_validators_root: Eth2Digest,
       basePath, dbname: string,
       modes: set[SlashProtDBMode]
    ): T =

  doAssert modes.card >= 1, "No slashing protection mode chosen. Choose a v1, a v2 or v1 and v2 slashing DB mode."
  doAssert not(
    kCompleteArchive in modes and
    kLowWatermark in modes), "Mode(s): " & $modes & ". Choose only one of V2 DB modes."

  new result
  result.modes = modes

proc init(
       T: type SlashingProtectionDB,
       genesis_validators_root: Eth2Digest,
       basePath, dbname: string
     ): T =
  init(
    T, genesis_validators_root, basePath, dbname,
    modes = {kLowWatermark}
  )

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
    result.modes.incl(kCompleteArchive)
  except CatchableError as err:
    error "Failed to load the Slashing protection database", err = err.msg
    quit 1

proc checkSlashableBlockProposal(
       db: SlashingProtectionDB,
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       slot: Slot
     ): Result[void, BadProposal] =
  checkSlashableBlockProposal(Opt.some(index), validator, slot)

proc registerBlock*(
       index: ValidatorIndex,
       validator: ValidatorPubKey,
       slot: Slot, block_signing_root: Eth2Digest): Result[void, BadProposal] =
  registerBlock(Opt.some(index), validator, slot, block_signing_root)

template withContext(db: SlashingProtectionDB, body: untyped): untyped =
  db.db_v2.withContext:
    template registerAttestationInContext(
      index: ValidatorIndex,
        validator: ValidatorPubKey,
        source, target: Epoch,
        attestation_signing_root: Eth2Digest): Result[void, BadVote] =
      registerAttestationInContextV2(Opt.some(index), validator, source, target, attestation_signing_root)
    block:
      body
