import
  std/[os, strutils, streams, parsecsv],
  stew/[io2, byteutils], chronicles, confutils, snappy,
  ../beacon_chain/spec/datatypes/base,
  ./ncli_common

when defined(posix):
  import system/ansi_c

type
  AggregatorConf = object
    startEpoch {.
      name: "start-epoch"
      abbr: "s"
      desc: "The first epoch which to be aggregated. " &
            "By default use the first epoch for which has a file" .}: Option[uint64]
    endEpoch {.
      name: "end-epoch"
      abbr: "e"
      desc: "The last epoch which to be aggregated. " &
            "By default use the last epoch for which has a file" .}: Option[uint64]
    resolution {.
      defaultValue: 225,
      name: "resolution"
      abbr: "r"
      desc: "How many epochs to be aggregated in a single file" .}: uint
    inputDir {.
      name: "input-dir"
      abbr: "i"
      desc: "The directory with the epoch info files" .}: InputDir
    outputDir {.
      defaultValue: ""
      name: "output-dir"
      abbr: "o"
      desc: "The directory where aggregated file to be written. " &
            "By default use the same directory as the input one"}: InputDir

var shutDown = false

proc determineStartAndEndEpochs(config: AggregatorConf):
    tuple[startEpoch, endEpoch: Epoch] =
  if config.startEpoch.isNone or config.endEpoch.isNone:
    (result.startEpoch, result.endEpoch) = getEpochRange(config.inputDir.string)
  if config.startEpoch.isSome:
    result.startEpoch = config.startEpoch.get.Epoch
  if config.endEpoch.isSome:
    result.endEpoch = config.endEpoch.get.Epoch
  if result.startEpoch > result.endEpoch:
    fatal "Start epoch cannot be bigger than the end epoch.",
          startEpoch = result.startEpoch, endEpoch = result.endEpoch
    quit QuitFailure

proc checkIntegrity(startEpoch, endEpoch: Epoch, dir: string) =
  for epoch in startEpoch .. endEpoch:
    let filePath = getFilePathForEpoch(epoch, dir)
    if not filePath.fileExists:
      fatal "File for epoch does not exist.", epoch = epoch, filePath = filePath
      quit QuitFailure

proc parseRow(csvRow: CsvRow): RewardsAndPenalties =
  result = RewardsAndPenalties(
    source_outcome: parseBiggestInt(csvRow[0]),
    max_source_reward: parseBiggestUInt(csvRow[1]),
    target_outcome: parseBiggestInt(csvRow[2]),
    max_target_reward: parseBiggestUInt(csvRow[3]),
    head_outcome: parseBiggestInt(csvRow[4]),
    max_head_reward: parseBiggestUInt(csvRow[5]),
    inclusion_delay_outcome: parseBiggestInt(csvRow[6]),
    max_inclusion_delay_reward: parseBiggestUInt(csvRow[7]),
    sync_committee_outcome: parseBiggestInt(csvRow[8]),
    max_sync_committee_reward: parseBiggestUInt(csvRow[9]),
    proposer_outcome: parseBiggestInt(csvRow[10]),
    inactivity_penalty: parseBiggestUInt(csvRow[11]),
    slashing_outcome: parseBiggestInt(csvRow[12]),
    deposits: parseBiggestUInt(csvRow[13]))
  if csvRow[14].len > 0:
    result.inclusion_delay = some(parseBiggestUInt(csvRow[14]))

proc `+=`(lhs: var RewardsAndPenalties, rhs: RewardsAndPenalties) =
  lhs.source_outcome += rhs.source_outcome
  lhs.max_source_reward += rhs.max_source_reward
  lhs.target_outcome += rhs.target_outcome
  lhs.max_target_reward += rhs.max_target_reward
  lhs.head_outcome += rhs.head_outcome
  lhs.max_head_reward += rhs.max_head_reward
  lhs.inclusion_delay_outcome += rhs.inclusion_delay_outcome
  lhs.max_inclusion_delay_reward += rhs.max_inclusion_delay_reward
  lhs.sync_committee_outcome += rhs.sync_committee_outcome
  lhs.max_sync_committee_reward += rhs.max_sync_committee_reward
  lhs.proposer_outcome += rhs.proposer_outcome
  lhs.inactivity_penalty += rhs.inactivity_penalty
  lhs.slashing_outcome += rhs.slashing_outcome
  lhs.deposits += rhs.deposits
  if lhs.inclusion_delay.isSome:
    if rhs.inclusion_delay.isSome:
      lhs.inclusion_delay.get += rhs.inclusion_delay.get
  else:
    if rhs.inclusion_delay.isSome:
      lhs.inclusion_delay = some(rhs.inclusion_delay.get)

proc average(rp: var RewardsAndPenalties,
             averageInclusionDelay: var Option[float],
             epochsCount: uint, inclusionDelaysCount: uint64) =
  rp.source_outcome = rp.source_outcome div epochsCount.int64
  rp.max_source_reward = rp.max_source_reward div epochsCount
  rp.target_outcome = rp.target_outcome div epochsCount.int64
  rp.max_target_reward = rp.max_target_reward div epochsCount
  rp.head_outcome = rp.head_outcome div epochsCount.int64
  rp.max_head_reward = rp.max_head_reward div epochsCount
  rp.inclusion_delay_outcome = rp.inclusion_delay_outcome div epochsCount.int64
  rp.max_inclusion_delay_reward = rp.max_inclusion_delay_reward div epochsCount
  rp.sync_committee_outcome = rp.sync_committee_outcome div epochsCount.int64
  rp.max_sync_committee_reward = rp.max_sync_committee_reward div epochsCount
  rp.proposer_outcome = rp.proposer_outcome div epochsCount.int64
  rp.inactivity_penalty = rp.inactivity_penalty div epochsCount
  rp.slashing_outcome = rp.slashing_outcome div epochsCount.int64
  if rp.inclusion_delay.isSome:
    doAssert inclusionDelaysCount != 0
    averageInclusionDelay = some(
      rp.inclusion_delay.get.float / inclusionDelaysCount.float)
  else:
    doAssert inclusionDelaysCount == 0
    averageInclusionDelay = none(float)

proc getFilePathForEpochs(startEpoch, endEpoch: Epoch, dir: string): string =
  let fileName = epochAsString(startEpoch) & "_"  &
                 epochAsString(endEpoch) & epochFileNameExtension
  dir / fileName

proc aggregateEpochs(startEpoch, endEpoch: Epoch, resolution: uint,
                     inputDir, outputDir: string) =
  if startEpoch > endEpoch:
    fatal "Start epoch cannot be larger than the end one.",
          startEpoch = startEpoch, endEpoch = endEpoch
    quit QuitFailure

  info "Aggregating epochs ...", startEpoch = startEpoch, endEpoch = endEpoch,
       inputDir = inputDir, outputDir = outputDir

  var rewardsAndPenalties: seq[RewardsAndPenalties]
  var participationEpochsCount: seq[uint]
  var inclusionDelaysCount: seq[uint]
  var epochsAggregated = 0'u

  for epoch in startEpoch .. endEpoch:
    let filePath = getFilePathForEpoch(epoch, inputDir)
    info "Processing file ...", file = filePath

    let data = io2.readAllBytes(filePath)
    doAssert data.isOk
    let dataStream = newStringStream(
      string.fromBytes(snappy.decode(
        data.get.toOpenArray(0, data.get.len - 1))))

    var csvParser: CsvParser
    csvParser.open(dataStream, filePath)

    var validatorsCount = 0'u
    while csvParser.readRow:
      inc validatorsCount
      let rp = parseRow(csvParser.row)

      if validatorsCount > participationEpochsCount.len.uint:
        rewardsAndPenalties.add rp
        participationEpochsCount.add 1
        if rp.inclusionDelay.isSome:
          inclusionDelaysCount.add 1
        else:
          inclusionDelaysCount.add 0
      else:
        rewardsAndPenalties[validatorsCount - 1] += rp
        inc participationEpochsCount[validatorsCount - 1]
        if rp.inclusionDelay.isSome:
          inc inclusionDelaysCount[validatorsCount - 1]

    inc epochsAggregated

    if epochsAggregated == resolution or epoch == endEpoch or shutDown:
      var csvLines: string
      for i in 0 ..< participationEpochsCount.len:
        var averageInclusionDelay: Option[float]
        average(rewardsAndPenalties[i], averageInclusionDelay,
                participationEpochsCount[i], inclusionDelaysCount[i])
        csvLines &= serializeToCsv(
          rewardsAndPenalties[i], averageInclusionDelay)

      let fileName = getFilePathForEpochs(
        epoch - epochsAggregated + 1, epoch, outputDir)
      info "Writing file ...", fileName = fileName

      var result = io2.removeFile(fileName)
      doAssert result.isOk
      result = io2.writeFile(fileName, snappy.encode(csvLines.toBytes))
      doAssert result.isOk

      if shutDown:
        quit QuitSuccess

      participationEpochsCount.setLen(0)
      rewardsAndPenalties.setLen(0)
      inclusionDelaysCount.setLen(0)
      epochsAggregated = 0

proc controlCHook {.noconv.} =
  notice "Shutting down after having received SIGINT."
  shutDown = true

proc exitOnSigterm(signal: cint) {.noconv.} =
  notice "Shutting down after having received SIGTERM."
  shutDown = true

proc main =
  setControlCHook(controlCHook)
  when defined(posix):
    c_signal(SIGTERM, exitOnSigterm)

  let config = load AggregatorConf
  let (startEpoch, endEpoch) = config.determineStartAndEndEpochs
  if endEpoch == 0:
    fatal "Not found epoch info files in the directory.",
          inputDir = config.inputDir
    quit QuitFailure

  checkIntegrity(startEpoch, endEpoch, config.inputDir.string)

  let outputDir =
    if config.outputDir.string.len > 0:
      config.outputDir
    else:
      config.inputDir

  aggregateEpochs(startEpoch, endEpoch, config.resolution,
                  config.inputDir.string, outputDir.string)

when isMainModule:
  main()
