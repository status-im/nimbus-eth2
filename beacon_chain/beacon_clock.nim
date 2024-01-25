# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/math,
  chronos/timer, chronicles,
  ./spec/beacon_time

from times import Time, getTime, fromUnix, `<`, `-`, inNanoseconds

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
    ## https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/fork-choice.md#fork-choice
    ##
    # TODO consider NTP and network-adjusted timestamps as outlined here:
    #      https://ethresear.ch/t/network-adjusted-timestamps/4187
    genesis: Time

  GetBeaconTimeFn* = proc(): BeaconTime {.gcsafe, raises: [].}

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
    (true, nanoseconds((t - now).nanoseconds))
  else:
    (false, nanoseconds((now - t).nanoseconds))

proc fromNow*(c: BeaconClock, slot: Slot): tuple[inFuture: bool, offset: Duration] =
  c.fromNow(slot.start_beacon_time())

proc durationToNextSlot*(c: BeaconClock): Duration =
  let
    currentTime = c.now()
    currentSlot = currentTime.toSlot()

  if currentSlot.afterGenesis:
    let nextSlot = currentSlot.slot + 1
    nanoseconds(
      (nextSlot.start_beacon_time() - currentTime).nanoseconds)
  else:
    # absoluteTime = BeaconTime(-currentTime.ns_since_genesis).
    let
      absoluteTime = Slot(0).start_beacon_time() +
        (Slot(0).start_beacon_time() - currentTime)
      timeToNextSlot = absoluteTime - currentSlot.slot.start_beacon_time()
    nanoseconds(timeToNextSlot.nanoseconds)

proc durationToNextEpoch*(c: BeaconClock): Duration =
  let
    currentTime = c.now()
    currentSlot = currentTime.toSlot()

  if currentSlot.afterGenesis:
    let nextEpochSlot = (currentSlot.slot.epoch() + 1).start_slot()
    nanoseconds(
      (nextEpochSlot.start_beacon_time() - currentTime).nanoseconds)
  else:
    # absoluteTime = BeaconTime(-currentTime.ns_since_genesis).
    let
      absoluteTime = Slot(0).start_beacon_time() +
        (Slot(0).start_beacon_time() - currentTime)
      timeToNextEpoch = absoluteTime -
        currentSlot.slot.epoch().start_slot().start_beacon_time()
    nanoseconds(timeToNextEpoch.nanoseconds)

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
