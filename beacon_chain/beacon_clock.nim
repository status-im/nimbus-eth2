# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/math,
  results,
  chronos/timer, chronicles,
  ./spec/beacon_time

from std/times import
  Time, getTime, fromUnix, toUnix, `<`, `-`, inNanoseconds, inSeconds

export timer.Duration, Moment, now, beacon_time

type
  BeaconClock* = object
    ## The beacon clock represents time as it passes on a beacon chain. Beacon
    ## time is locked to unix time, starting at a particular offset set during
    ## beacon chain instantiation.
    ##
    ## Time on the beacon chain determines what actions should be taken and
    ## which blocks are valid - in particular, blocks are not valid if they
    ## come from the future as seen from the local clock.
    ##
    ## https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/fork-choice.md#fork-choice
    ##
    # TODO consider NTP and network-adjusted timestamps as outlined here:
    #      https://ethresear.ch/t/network-adjusted-timestamps/4187
    timeParams: TimeParams
    genesis: Time

  GetBeaconTimeFn* = proc(): BeaconTime {.gcsafe, raises: [].}

proc init*(
    T: type BeaconClock,
    timeParams: TimeParams,
    genesis_time: uint64): Opt[T] =
  let
    MIN_GENESIS_TIME = GENESIS_SLOT * timeParams.SLOT_DURATION.seconds.uint64
    MAX_GENESIS_TIME =
      # Since we'll be converting beacon time differences to nanoseconds,
      # the time can't be outrageously far from now
      getTime().toUnix().uint64 +
      100'u64 * 365'u64 * 24'u64 * 60'u64 * 60'u64
  if timeParams.SLOT_DURATION notin MIN_SLOT_DURATION .. MAX_SLOT_DURATION or
      genesis_time notin MIN_GENESIS_TIME .. MAX_GENESIS_TIME:
    Opt.none(BeaconClock)
  else:
    let
      unixGenesis = fromUnix(genesis_time.int64)
      # GENESIS_SLOT offsets slot time, but to simplify calculations, we apply
      # that offset to genesis instead of applying it at every time conversion
      unixGenesisOffset = fromUnix(
        (GENESIS_SLOT.int64 * timeParams.SLOT_DURATION).seconds)

    Opt.some T(
      timeParams: timeParams,
      genesis: (unixGenesis - unixGenesisOffset).inSeconds.fromUnix)

func timeParams*(c: BeaconClock): TimeParams =
  c.timeParams  # Readonly

func toBeaconTime*(c: BeaconClock, t: Time): BeaconTime =
  BeaconTime(ns_since_genesis: inNanoseconds(t - c.genesis))

func toSlot*(c: BeaconClock, t: Time): tuple[afterGenesis: bool, slot: Slot] =
  c.toBeaconTime(t).toSlot(c.timeParams)

proc now*(c: BeaconClock): BeaconTime =
  ## Current time, in slots - this may end up being less than GENESIS_SLOT(!)
  toBeaconTime(c, getTime())

proc currentSlot*(c: BeaconClock): Slot =
  c.now.slotOrZero(c.timeParams)

func getBeaconTimeFn*(c: BeaconClock): GetBeaconTimeFn =
  return proc(): BeaconTime = c.now()

proc fromNow*(
    c: BeaconClock, t: BeaconTime): tuple[inFuture: bool, offset: Duration] =
  let now = c.now()
  if t > now:
    (true, nanoseconds((t - now).nanoseconds))
  else:
    (false, nanoseconds((now - t).nanoseconds))

proc fromNow*(
    c: BeaconClock, slot: Slot): tuple[inFuture: bool, offset: Duration] =
  c.fromNow(slot.start_beacon_time(c.timeParams))

func durationOrZero*(d: tuple[inFuture: bool, offset: Duration]): Duration =
  if d.inFuture:
    d.offset
  else:
    ZeroDuration

func nextSlotStartTime*(
    exSlot: tuple[afterGenesis: bool, slot: Slot],
    timeParams: TimeParams): BeaconTime =
  if exSlot.afterGenesis:
    (exSlot.slot + 1).start_beacon_time(timeParams)
  else:
    let
      genesisTime = GENESIS_SLOT.start_beacon_time(timeParams)
      timeDiff =
        exSlot.slot.start_beacon_time(timeParams) -
        genesisTime
    genesisTime - timeDiff

func nextEpochStartTime*(
    exSlot: tuple[afterGenesis: bool, slot: Slot],
    timeParams: TimeParams): BeaconTime =
  if exSlot.afterGenesis:
    (exSlot.slot.epoch + 1).start_slot.start_beacon_time(timeParams)
  else:
    let
      genesisTime = GENESIS_SLOT.start_beacon_time(timeParams)
      timeDiff =
        exSlot.slot.epoch.start_slot.start_beacon_time(timeParams) -
        genesisTime
    genesisTime - timeDiff

func saturate*(d: tuple[inFuture: bool, offset: Duration]): Duration =
  if d.inFuture: d.offset else: seconds(0)

func shortLog*(d: Duration): string =
  $d

func toFloatSeconds*(d: Duration): float =
  float(milliseconds(d)) / 1000.0

func fromFloatSeconds*(T: type Duration, f: float): Duration =
  case classify(f)
  of fcNormal:
    if f >= float(int64.high() div 1_000_000_000): InfiniteDuration
    elif f <= 0: ZeroDuration
    else: nanoseconds(int64(f * 1_000_000_000))
  of fcSubnormal, fcZero, fcNegZero, fcNan, fcNegInf: ZeroDuration
  of fcInf: InfiniteDuration

chronicles.formatIt Duration: $it

const MinSignificantProcessingDuration* = 250.millis
