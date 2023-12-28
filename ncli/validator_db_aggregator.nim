# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[parsecsv, streams],
  stew/[io2, byteutils], chronicles, confutils, snappy,
  ../beacon_chain/spec/datatypes/base,
  ./ncli_common

from std/os import fileExists
from std/strutils import parseBiggestInt, parseBiggestUInt

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

  ValidatorDbAggregator* {.requiresInit.} = object
    outputDir: string
    resolution: uint
    endEpoch: Epoch
    epochsAggregated: uint
    aggregatedRewardsAndPenalties: seq[RewardsAndPenalties]
    participationEpochsCount: seq[uint]
    inclusionDelaysCount: seq[uint]

func init*(T: type ValidatorDbAggregator, outputDir: string,
           resolution: uint, endEpoch: Epoch): T =
  const initialCapacity = 1 shl 16
  ValidatorDbAggregator(
    outputDir: outputDir,
    resolution: resolution,
    endEpoch: endEpoch,
    epochsAggregated: 0,
    aggregatedRewardsAndPenalties:
      newSeqOfCap[RewardsAndPenalties](initialCapacity),
    participationEpochsCount: newSeqOfCap[uint](initialCapacity),
    inclusionDelaysCount: newSeqOfCap[uint](initialCapacity))

var shouldShutDown = false

proc determineStartAndEndEpochs(config: AggregatorConf):
    tuple[startEpoch, endEpoch: Epoch] =
  if config.startEpoch.isNone or config.endEpoch.isNone:
    (result.startEpoch, result.endEpoch) = getUnaggregatedFilesEpochRange(
      config.inputDir.string)
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

func parseRow(csvRow: CsvRow): RewardsAndPenalties =
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

func `+=`(lhs: var RewardsAndPenalties, rhs: RewardsAndPenalties) =
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

func average(rp: var RewardsAndPenalties,
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


func addValidatorData*(aggregator: var ValidatorDbAggregator,
                       index: int, rp: RewardsAndPenalties) =
  if index >= aggregator.participationEpochsCount.len:
    aggregator.aggregatedRewardsAndPenalties.add rp
    aggregator.participationEpochsCount.add 1
    if rp.inclusion_delay.isSome:
      aggregator.inclusionDelaysCount.add 1
    else:
      aggregator.inclusionDelaysCount.add 0
  else:
    aggregator.aggregatedRewardsAndPenalties[index] += rp
    inc aggregator.participationEpochsCount[index]
    if rp.inclusion_delay.isSome:
      inc aggregator.inclusionDelaysCount[index]

proc advanceEpochs*(aggregator: var ValidatorDbAggregator, epoch: Epoch,
                    shouldShutDown: bool) =
  inc aggregator.epochsAggregated

  if aggregator.epochsAggregated != aggregator.resolution and
     aggregator.endEpoch != epoch and not shouldShutDown:
    return

  var csvLines = newStringOfCap(1000000)
  for i in 0 ..< aggregator.participationEpochsCount.len:
    var averageInclusionDelay: Option[float]
    average(aggregator.aggregatedRewardsAndPenalties[i], averageInclusionDelay,
            aggregator.participationEpochsCount[i],
            aggregator.inclusionDelaysCount[i])
    csvLines &= serializeToCsv(
      aggregator.aggregatedRewardsAndPenalties[i], averageInclusionDelay)

  let fileName = getFilePathForEpochs(
    epoch - aggregator.epochsAggregated + 1, epoch, aggregator.outputDir)
  info "Writing file ...", fileName = fileName

  var result = io2.removeFile(fileName)
  doAssert result.isOk
  result = io2.writeFile(fileName, snappy.encode(csvLines.toBytes))
  doAssert result.isOk

  aggregator.participationEpochsCount.setLen(0)
  aggregator.aggregatedRewardsAndPenalties.setLen(0)
  aggregator.inclusionDelaysCount.setLen(0)
  aggregator.epochsAggregated = 0

when isMainModule:
  when defined(posix):
    import system/ansi_c

  proc aggregateEpochs(startEpoch, endEpoch: Epoch, resolution: uint,
                       inputDir, outputDir: string) =
    if startEpoch > endEpoch:
      fatal "Start epoch cannot be larger than the end one.",
            startEpoch = startEpoch, endEpoch = endEpoch
      quit QuitFailure

    info "Aggregating epochs ...", startEpoch = startEpoch, endEpoch = endEpoch,
         inputDir = inputDir, outputDir = outputDir

    var aggregator = ValidatorDbAggregator.init(outputDir, resolution, endEpoch)

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

      var validatorsCount = 0
      while csvParser.readRow:
        inc validatorsCount
        let rp = parseRow(csvParser.row)
        aggregator.addValidatorData(validatorsCount - 1, rp)

      aggregator.advanceEpochs(epoch, shouldShutDown)

      if shouldShutDown:
        quit QuitSuccess

  proc controlCHook {.noconv.} =
    notice "Shutting down after having received SIGINT."
    shouldShutDown = true

  proc exitOnSigterm(signal: cint) {.noconv.} =
    notice "Shutting down after having received SIGTERM."
    shouldShutDown = true

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

  main()
