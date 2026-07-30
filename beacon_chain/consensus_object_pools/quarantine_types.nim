# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  stew/bitops2,
  chronos,
  ../spec/digest

type
  MissingItem* = object
    tries*: int

  FetchRecord* = object
    root*: Eth2Digest

  MissingTable* = object
    items*: Table[Eth2Digest, MissingItem]
      ## Table of missing items
    maxCapacity*: int
      ## Max capacity of missing items
    maxRetries*: int
      ## Exponential backoff, double interval between each attempt
    event*: AsyncEvent
      ## Event that will be set when the number of elements changes

func init*(
    T: type MissingTable,
    maxCapacity: int = 1024,
    maxRetries: int = 8
): T =
  T(
    maxCapacity: maxCapacity,
    maxRetries: 1 shl (maxRetries - 1),
    event: nil
  )

func init*(
    T: type MissingTable,
    event: AsyncEvent,
    maxCapacity: int = 1024,
    maxRetries: int = 8
): T =
  T(
    maxCapacity: maxCapacity,
    maxRetries: 1 shl (maxRetries - 1),
    event: event
  )

func len*(self: MissingTable): int =
  self.items.len()

func isFull*(self: MissingTable): bool =
  self.len() >= self.maxCapacity

proc add*(self: var MissingTable, root: Eth2Digest) =
  if self.isFull():
    return
  if self.items.hasKeyOrPut(root, MissingItem()):
    if not(isNil(self.event)):
      self.event.fire()

proc checkMissing*(self: var MissingTable, max: int): seq[FetchRecord] =
  # Remove items that have reached max retries
  var done: seq[Eth2Digest]
  for k, v in self.items.mpairs():
    if v.tries >= self.maxRetries:
      done.add(k)
  for k in done:
    self.items.del(k)

  if (len(done) > 0) and not(isNil(self.event)):
    self.event.fire()

  # Get items
  for k, v in self.items.mpairs():
    v.tries += 1
    if countOnes(uint64(v.tries)) == 1:
      result.add(FetchRecord(root: k))
      if result.len() >= max:
        break

proc del*(self: var MissingTable, root: Eth2Digest) =
  var value: MissingItem
  if self.items.pop(root, value):
    if not(isNil(self.event)):
      self.event.fire()

proc resetItems*(self: var MissingTable) =
  let length = len(self.items)
  self.items.reset()
  if (length > 0) and not(isNil(self.event)):
    self.event.fire()

func contains*(self: MissingTable, root: Eth2Digest): bool =
  root in self.items
