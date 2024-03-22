import
  ./spec/beacon_time

from std/times import Time, getTime, `-`, inNanoseconds

type
  BeaconClock* = object
    genesis: Time

func toBeaconTime(c: BeaconClock, t: Time): BeaconTime =
  BeaconTime(ns_since_genesis: inNanoseconds(t - c.genesis))

proc now*(c: BeaconClock): BeaconTime =
  ## Current time, in slots - this may end up being less than GENESIS_SLOT(!)
  toBeaconTime(c, getTime())
