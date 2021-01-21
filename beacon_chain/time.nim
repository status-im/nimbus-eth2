{.push raises: [Defect].}

import
  chronos, chronicles,
  spec/datatypes

from times import Time, getTime, fromUnix, `<`, `-`, inNanoseconds

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
    ## https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/fork-choice.md#fork-choice
    ##
    # TODO replace time in chronos with a proper unit type, then this code can
    #      follow:
    #      https://github.com/status-im/nim-chronos/issues/15
    # TODO consider NTP and network-adjusted timestamps as outlined here:
    #      https://ethresear.ch/t/network-adjusted-timestamps/4187
    genesis: Time

  BeaconTime* = distinct Duration ## Nanoseconds from beacon genesis time

proc init*(T: type BeaconClock, genesis_time: uint64): T =
  let
    unixGenesis = fromUnix(genesis_time.int64)
    # GENESIS_SLOT offsets slot time, but to simplify calculations, we apply that
    # offset to genesis instead of applying it at every time conversion
    unixGenesisOffset = times.seconds(int(GENESIS_SLOT * SECONDS_PER_SLOT))

  T(genesis: unixGenesis - unixGenesisOffset)

proc init*(T: type BeaconClock, state: BeaconState): T =
  ## Initialize time from a beacon state. The genesis time of a beacon state is
  ## constant throughout its lifetime, so the state from any slot will do,
  ## including the genesis state.
  BeaconClock.init(state.genesis_time)

template `<`*(a, b: BeaconTime): bool =
  Duration(a) < Duration(b)

template `<=`*(a, b: BeaconTime): bool =
  Duration(a) <= Duration(b)

template `+`*(t: BeaconTime, offset: Duration): BeaconTime =
  BeaconTime(Duration(t) + offset)

template `-`*(t: BeaconTime, offset: Duration): BeaconTime =
  BeaconTime(nanoseconds(nanoseconds(Duration(t)) - nanoseconds(offset)))

template `-`*(a, b: BeaconTime): Duration =
  nanoseconds(nanoseconds(Duration(a)) - nanoseconds(Duration(b)))

func toSlot*(t: BeaconTime): tuple[afterGenesis: bool, slot: Slot] =
  let ti = seconds(Duration(t))
  if ti >= 0:
    (true, Slot(uint64(ti) div SECONDS_PER_SLOT))
  else:
    (false, Slot(uint64(-ti) div SECONDS_PER_SLOT))

func slotOrZero*(time: BeaconTime): Slot =
  let exSlot = time.toSlot
  if exSlot.afterGenesis: exSlot.slot
  else: Slot(0)

func toBeaconTime*(c: BeaconClock, t: Time): BeaconTime =
  BeaconTime(nanoseconds(inNanoseconds(t - c.genesis)))

func toSlot*(c: BeaconClock, t: Time): tuple[afterGenesis: bool, slot: Slot] =
  c.toBeaconTime(t).toSlot()

func toBeaconTime*(s: Slot, offset = Duration()): BeaconTime =
  BeaconTime(seconds(int64(uint64(s) * SECONDS_PER_SLOT)) + offset)

proc now*(c: BeaconClock): BeaconTime =
  ## Current time, in slots - this may end up being less than GENESIS_SLOT(!)
  toBeaconTime(c, getTime())

proc fromNow*(c: BeaconClock, t: BeaconTime): tuple[inFuture: bool, offset: Duration] =
  let now = c.now()
  if t > now:
    (true, t - now)
  else:
    (false, now - t)

proc fromNow*(c: BeaconClock, slot: Slot): tuple[inFuture: bool, offset: Duration] =
  c.fromNow(slot.toBeaconTime())

func saturate*(d: tuple[inFuture: bool, offset: Duration]): Duration =
  if d.inFuture: d.offset else: seconds(0)

proc addTimer*(fromNow: Duration, cb: CallbackFunc, udata: pointer = nil) =
  try:
    discard setTimer(Moment.now() + fromNow, cb, udata)
  except Exception as e:
    # TODO https://github.com/status-im/nim-chronos/issues/94
    # shouldn't happen because we should have initialized chronos by now
    # https://github.com/nim-lang/Nim/issues/10288 - sigh
    raiseAssert e.msg

func humaneStr*(a: Duration): string {.inline.} =
  ## Returns a "humane" string representation of the duration that uses
  ## the most appropriate unit type depending on the actual Duration.
  var v = a.nanoseconds
  let days = v div nanoseconds(Day)
  if days > 0:
    if days >= 14:
      return $(v div nanoseconds(Week)) & " weeks"
    elif days >= 2:
      return $days & " days"

  let hours = v div nanoseconds(Hour)
  if hours > 0:
    if hours >= 2:
      result = $hours & " hours"
    else:
      result = "1 hour"
    v = v mod nanoseconds(Hour)

  let minutes = v div nanoseconds(Minute)
  if minutes > 0:
    if hours > 0:
      result.add " "
    if minutes >= 2:
      result.add $minutes
      result.add " minutes"
    else:
      result.add "1 minute"
    v = v mod nanoseconds(Minute)

  let
    isMoreThanAMinute = minutes > 0 or hours > 0
    seconds = v div nanoseconds(Second)

  if seconds > 0:
    if isMoreThanAMinute:
      result.add " "
      if seconds >= 2:
        result.add $seconds
        result.add " seconds"
      else:
        result.add "1 second"
    else:
      result = $seconds
      v = v mod nanoseconds(Second)
      let milliseconds = v div nanoseconds(Millisecond)
      if milliseconds > 0:
        let millisecondsStr = $milliseconds
        result.add "."
        for _ in millisecondsStr.len ..< 3: result.add "0"
        result.add millisecondsStr
      elif seconds == 1:
        return "1 second"
      result.add " seconds"
    return

  if isMoreThanAMinute:
    return

  let milliseconds = v div nanoseconds(Millisecond)
  if milliseconds >= 2:
    return $milliseconds & " milliseconds"

  let microseconds = v div nanoseconds(Microsecond)
  if microseconds >= 2:
    return $microseconds & " microseconds"

  let nanoseconds = v div nanoseconds(Nanosecond)
  if nanoseconds == 1:
    return "1 nanosecond"

  return $nanoseconds & " nanoseconds"

func shortLog*(d: Duration): string =
  $d

func toFloatSeconds*(d: Duration): float =
  float(milliseconds(d)) / 1000.0

func `$`*(v: BeaconTime): string = $Duration(v)
func shortLog*(v: BeaconTime): string = humaneStr Duration(v)

chronicles.formatIt Duration: humaneStr(it)
chronicles.formatIt BeaconTime: humaneStr(Duration it)

