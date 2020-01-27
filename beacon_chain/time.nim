import
  chronos,
  spec/[datatypes]

from times import Time, getTime, fromUnix, `<`, `-`

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
    ## https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/fork-choice.md#fork-choice
    ##
    # TODO replace time in chronos with a proper unit type, then this code can
    #      follow:
    #      https://github.com/status-im/nim-chronos/issues/15
    # TODO consider NTP and network-adjusted timestamps as outlined here:
    #      https://ethresear.ch/t/network-adjusted-timestamps/4187
    genesis: Time

  BeaconTime* = distinct int64 ## Seconds from beacon genesis time

proc init*(T: type BeaconClock, state: BeaconState): T =
  ## Initialize time from a beacon state. The genesis time of a beacon state is
  ## constant throughout its lifetime, so the state from any slot will do,
  ## including the genesis state.

  let
    unixGenesis = fromUnix(state.genesis_time.int64)
    # GENESIS_SLOT offsets slot time, but to simplify calculations, we apply that
    # offset to genesis instead of applying it at every time conversion
    unixGenesisOffset = times.seconds(int(GENESIS_SLOT * SECONDS_PER_SLOT))

  T(genesis: unixGenesis - unixGenesisOffset)

template `<`*(a, b: BeaconTime): bool =
  int64(a) < int64(b)

template `<=`*(a, b: BeaconTime): bool =
  int64(a) <= int64(b)

func toSlot*(t: BeaconTime): tuple[afterGenesis: bool, slot: Slot] =
  let ti = t.int64
  if ti >= 0:
    (true, Slot(uint64(ti) div SECONDS_PER_SLOT))
  else:
    (false, Slot(uint64(-ti) div SECONDS_PER_SLOT))

func toBeaconTime*(c: BeaconClock, t: Time): BeaconTime =
  BeaconTime(times.inSeconds(t - c.genesis))

func toSlot*(c: BeaconClock, t: Time): tuple[afterGenesis: bool, slot: Slot] =
  c.toBeaconTime(t).toSlot()

func toBeaconTime*(s: Slot, offset = chronos.seconds(0)): BeaconTime =
  BeaconTime(int64(uint64(s) * SECONDS_PER_SLOT) + seconds(offset))

proc now*(c: BeaconClock): BeaconTime =
  ## Current time, in slots - this may end up being less than GENESIS_SLOT(!)
  toBeaconTime(c, getTime())

proc fromNow*(c: BeaconClock, t: BeaconTime): tuple[inFuture: bool, offset: Duration] =
  let now = c.now()

  if int64(t) > int64(now):
    (true, seconds(int64(t) - int64(now)))
  else:
    (false, seconds(int64(now) - int64(t)))

proc fromNow*(c: BeaconClock, slot: Slot): tuple[inFuture: bool, offset: Duration] =
  c.fromNow(slot.toBeaconTime())

func saturate*(d: tuple[inFuture: bool, offset: Duration]): Duration =
  if d.inFuture: d.offset else: seconds(0)

proc addTimer*(fromNow: Duration, cb: CallbackFunc, udata: pointer = nil) =
  addTimer(Moment.now() + fromNow, cb, udata)

func shortLog*(d: Duration): string =
  let dd = int64(d.milliseconds())
  if dd < 1000:
    $dd & "ms"
  elif dd < 60 * 1000:
    $(dd div 1000) & "s"
  elif dd < 60 * 60 * 1000:
    let secs = dd div 1000
    var tmp = $(secs div 60) & "m"
    if (let frac = secs mod 60; frac > 0):
      tmp &= $frac & "s"
    tmp
  else:
    let mins = dd div 60 * 1000
    var tmp = $(mins div 60) & "h"
    if (let frac = mins mod 60; frac > 0):
      tmp &= $frac & "m"
    tmp

func shortLog*(v: BeaconTime): int64 = v.int64
