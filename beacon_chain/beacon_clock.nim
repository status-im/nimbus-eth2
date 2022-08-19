# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  std/math,
  chronos, chronicles,
  ./spec/beacon_time

from times import Time, getTime, fromUnix, `<`, `-`, inNanoseconds

export chronos.Duration, Moment, now

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
    ## https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.3/specs/phase0/fork-choice.md#fork-choice
    ##
    # TODO consider NTP and network-adjusted timestamps as outlined here:
    #      https://ethresear.ch/t/network-adjusted-timestamps/4187
    genesis: Time

  GetBeaconTimeFn* = proc(): BeaconTime {.gcsafe, raises: [Defect].}

proc init*(T: type BeaconClock, genesis_time: uint64): T =
  # ~290 billion years into the future
  doAssert genesis_time <= high(int64).uint64

  let
    unixGenesis = fromUnix(genesis_time.int64)
    # GENESIS_SLOT offsets slot time, but to simplify calculations, we apply that
    # offset to genesis instead of applying it at every time conversion
    unixGenesisOffset = times.seconds(int(GENESIS_SLOT * SECONDS_PER_SLOT))

  T(genesis: unixGenesis - unixGenesisOffset)

func toBeaconTime*(c: BeaconClock, t: Time): BeaconTime =
  BeaconTime(ns_since_genesis: inNanoseconds(t - c.genesis))

func toSlot*(c: BeaconClock, t: Time): tuple[afterGenesis: bool, slot: Slot] =
  c.toBeaconTime(t).toSlot()

proc now*(c: BeaconClock): BeaconTime =
  ## Current time, in slots - this may end up being less than GENESIS_SLOT(!)
  toBeaconTime(c, getTime())

func getBeaconTimeFn*(c: BeaconClock): GetBeaconTimeFn =
  return proc(): BeaconTime = c.now()

proc fromNow*(c: BeaconClock, t: BeaconTime): tuple[inFuture: bool, offset: Duration] =
  let now = c.now()
  if t > now:
    (true, chronos.nanoseconds((t - now).nanoseconds))
  else:
    (false, chronos.nanoseconds((now - t).nanoseconds))

proc fromNow*(c: BeaconClock, slot: Slot): tuple[inFuture: bool, offset: Duration] =
  c.fromNow(slot.start_beacon_time())

proc durationToNextSlot*(c: BeaconClock): Duration =
  let (afterGenesis, slot) = c.now().toSlot()
  if afterGenesis:
    c.fromNow(slot + 1'u64).offset
  else:
    c.fromNow(Slot(0)).offset

proc durationToNextEpoch*(c: BeaconClock): Duration =
  let (afterGenesis, slot) = c.now().toSlot()
  if afterGenesis:
    c.fromNow((slot.epoch + 1).start_slot()).offset
  else:
    c.fromNow(Epoch(0).start_slot()).offset

func saturate*(d: tuple[inFuture: bool, offset: Duration]): Duration =
  if d.inFuture: d.offset else: seconds(0)

proc sleepAsync*(t: TimeDiff): Future[void] =
  sleepAsync(chronos.nanoseconds(
    if t.nanoseconds < 0: 0'i64 else: t.nanoseconds))

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
