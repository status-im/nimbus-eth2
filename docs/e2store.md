# Introduction

The `e2store` (extension: `.e2s`) is a simple linear [TLV](https://en.wikipedia.org/wiki/Type-length-value) file for storing arbitrary items typically encoded using serialization techniques used in ethereum 2 in general: SSZ, varint, snappy.

# General structure

`e2s` files consist of repeated type-length-value records. Each record is variable-length, and unknown records can easily be skipped. In particular, `e2s` files are designed to:

* allow trivial implementations that are easy to audit
* allow append-only implementations
* allow future record types to be added, such as when the chain forks

The type and length are encoded in an 8-byte header which is directly followed by data.

```
record = header | data
header = type | length
type = Vector[byte, 2]
length = Vector[byte, 6]
```

The `length` is the first 6 bytes of a little-endian encoded `uint64`, not including the header itself. For example, the entry with header type `[0x22, 0x32]`, the length `4` and the bytes `[0x01, 0x02, 0x03, 0x04]` will be stored as the byte sequence `[0x22, 0x32, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]`.

`.e2s` files may freely be concatenated, and may contain out-of-order records.

Types that have the high bit in the first byte set (those in the range `[0x80-0xff]`) are application and/or vendor specific.

## Reading

The following python code can be used to read an e2 file:

```python
import sys, struct

def read_entry(f):
  header = f.read(8)
  if not header: return None

  typ = header[0:2] # 2 bytes of type
  dlen = struct.unpack("<q", header[2:8] + b"\0\0")[0] # 6 bytes of little-endian length

  data = f.read(dlen)

  return (typ, data)

def print_stats(name):
  with open(name, "rb") as f:
    sizes = {}
    entries = 0

    while True:
      (typ, data) = read_entry(f)

      if not typ:
        break
      entries += 1

      old = sizes.get(typ, (0, 0))
      sizes[typ] = (old[0] + len(data), old[1] + 1)

    print("Entries", entries)

    for k, v in dict(sorted(sizes.items())).items():
      print("type", k.hex(), "bytes", v[0], "count", v[1], "average", v[0] / v[1])
```


## Writing

`e2s` files are by design intended to be append-only, making them suitable for cold storage of finalized chain data.

# Known types

## Version

```
type: [0x65, 0x32]
```

The `version` type must be the first record in the file. Its type is `[0x65, 0x32]` (`e2` in ascii) and the length of its data field is always 0, thus the first 8 bytes of an `e2s` file are always `[0x65, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`. When a new version record is encountered, it applies to all records following the version entry - this can happen when two e2s files are concatenated.

## CompressedSignedBeaconBlock

```
type: [0x01, 0x00]
data: snappyFramed(ssz(SignedBeaconBlock))
```

`CompressedSignedBeackBlock` entries are entries whose data field matches the payload of `BeaconBlocksByRange` and `BeaconBlocksByRoot` chunks in the phase0 p2p specification. In particular, the SignedBeaconBlock is serialized using SSZ, then compressed using the snappy [framing format](https://github.com/google/snappy/blob/master/framing_format.txt).

## CompressedBeaconState

```
type: [0x02, 0x00]
data: snappyFramed(ssz(BeaconState))
```

`CompressedBeaconState` entries are entries whose data field match that of `CompressedSignedBeaconBlock` but carry a `BeaconState` instead.

## Empty

```
type: [0x00, 0x00]
```

The `Empty` type contains no data, but may have a length. The corresponding amount of data should be skiped while reading the file.

## SlotIndex

```
type: [0x69, 0x32]
data: starting-slot | index | index | index ... | count
```

`SlotIndex` records store offsets, in bytes, from the beginning of the index record to the beginning of the corresponding data at that slot. An offset of `0` indicates that no data is present for the given slot.

Each entry in the slot index is a fixed-length 8-byte signed integer, meaning that the entry for slot `N` can be found at index `(N * 8) + 16` in the index. The length of a `SlotIndex` record can be computed as `count * 8 + 24` - one entry for every slot and 8 bytes each for type header, starting slot and count. In particular, knowing where the slot index ends allows finding its beginning as well.

Only one entry per slot is supported, meaning that only one canonical history can be indexed this way.

A `SlotIndex` record may appear in a stand-alone file which by convention ends with `.e2i` - in this case, the offset is counted as if the index was appened to its corresponding data file - offsets are thus negative and counted from the end of the data file. In particular, if the index is simply appended to the data file, it does not change in contents.

### Reading

```python
def read_slot_index(f):
  # Read a slot index, assuming `f` is positioned at the end of the record
  record_end = f.tell()
  f.seek(-8, 1) # Relative seek to get count

  count = struct.unpack("<q", f.read(8))[0]

  record_start = record_end - (8 * count + 24)
  if record_start < 0:
    raise RuntimeError("Record count out of bounds")

  f.seek(record_start) # Absolute seek

  (typ, data) = read_entry(f)

  if typ != b"i2":
    raise RuntimeError("this is not an e2store index record")

  start_slot = struct.unpack("<q", data[0:8])[0]

  # Convert slot indices to absolute file offsets
  slot_entries = (data[(i+1) * 8:(i+2)*8] for i in range(0, (len(data)//8 - 2)))
  slot_offsets = [struct.unpack("<q", entry)[0] for entry in slot_entries]

  return (start_slot, record_start, slot_offsets)
```

# Era files

`.era` files are special instances of `.e2s` files that follow a more strict content format optimised for reading and long-term storage and distribution. Era files contain groups consisting of a state and the blocks that led up to it, limited to `SLOTS_PER_HISTORICAL_ROOT` slots each, allowing quick verification of the data contained in the file.

Each era is identified by when it ends. Thus, the genesis era is era 0, followed by era 1 which ends when slot 8192 has been processed, but the block that potentially exists at slot 8192 has not yet been applied.

## File name

`.era` file names follow a simple convention: `<config-name>-<era-number>-<era-count>-<short-historical-root>.era`:

* `config-name` is the `CONFIG_NAME` field of the runtime configation (`mainnet`, `prater`, etc)
* `era-number` is the number of the _last_ era stored in the file - for example, the genesis era file has number 0 - as a 5-digit 0-filled decimal integer
* `era-count` is the number of eras stored in the file, as a 5-digit 0-filled decimal integer
* `short-historical-root` is the first 4 bytes of the last historical root in the last state in the era file, lower-case hex-encoded (8 characters), except the genesis era which instead uses the `genesis_validators_root` field from the genesis state.
  * The root is available as `state.historical_roots[era - 1]` except for genesis, which is `state.genesis_validators_root`
  * Era files with multiple eras use the root of the highest era - this determines the earlier eras as well

An era file containing the mainnet genesis is thus named `mainnet-00000-00001-4b363db9.era`, and the era after that `mainnet-00001-00001-40cf2f3c.era`.

## Structure

An `.era` file is structured in the following way:

```
era := group+
group := Version | block* | era-state | other-entries* | slot-index(block)? | slot-index(state)
block := CompressedSignedBeaconBlock
era-state := CompressedBeaconState
```

The `block` entries of a group include all blocks pertaining to an era. For example, the group representing era one will have all blocks from slot 0 up to and including block 8191.

The `era-state` is the state of the slot that immediately follows the end of the era without applying blocks from the next era. For example, era 1 that covers the first 8192 slots will have all blocks applied up to slot 8191 and will `process_slots` up to 8192. The genesis group contains only the genesis state but no blocks.

`slot-index(state)` is a `SlotIndex` entry with `count = 1` for the `CompressedBeaconState` entry of that era, pointing out the offset where the state entry begins.

`slot-index(block)` is a `SlotIndex` entry with `count = SLOTS_PER_HISTORICAL_ROOT` for the `CompressedSignedBeaconBlock` entries in that era, pointing out the offsets of each block in the era. It is omitted for the genesis era.

`other-entries` is the extension point for future record types in the era file. The positioning of these allows the indices to continue to be looked up from the back.

The structure of the era file gives it the following properties:

* the indices at the end are fixed-length: they can be used to discover the beginning of an era if the end of it is known
* the start slot field of the state slot index idenfifies which era the group pertains to
* the state in the era file is the end state after having applied all the blocks in the era - the `block_roots` entries in the state can be used to discover the digest of the blocks - either to verify the intergrity of the era file or to quickly load block roots without computing them
* each group in the era file is full, indendent era file - eras can freely be split and combined

## Reading era files

```python
def read_era_file(name):
  # Print contents of an era file, backwards
  with open(name, "rb") as f:

    # Seek to end of file to figure out the indices of the state and blocks
    f.seek(0, 2)

    groups = 0
    while True:
      if f.tell() < 8:
        break

      (start_slot, state_index_start, state_slot_offsets) = read_slot_index(f)

      print(
        "State slot:", start_slot,
        "state index start:", state_index_start,
        "offsets", state_slot_offsets)

      # The start of the state index record is the end of the block index record, if any
      f.seek(state_index_start)

      # This can underflow! Python should complain when seeking - ymmv
      prev_group = state_index_start + state_slot_offsets[0] - 8
      if start_slot > 0:
        (block_slot, block_index_start, block_slot_offsets) = read_slot_index(f)

        print(
          "Block start slot:", block_slot,
          "block index start:", block_index_start,
          "offsets", len(block_slot_offsets))

        if any((x for x in block_slot_offsets if x != 0)):
          # This can underflow! Python should complain when seeking - ymmv
          prev_group = block_index_start + [x for x in block_slot_offsets if x != 0][0] - 8

      print("Previous group starts at:", prev_group)
      # The beginning of the first block (or the state, if there are no blocks)
      # is the end of the previous group
      f.seek(prev_group) # Skip header

      groups += 1
    print("Groups in file:", groups)
```

# FAQ

## Why snappy framed compression?

* The networking protocol uses snappy framed compression, avoiding the need to re-compress data to serve blocks
* Each entry can be decompressed separately
* It's fast and compresses decently - some compression stats for the first 100 eras:
  * Uncompressed: 8.4gb
  * Snappy compression: 4.7gb
  * `xz` of uncompressed: 3.8gb

## Why SLOTS_PER_HISTORICAL_ROOT blocks per state?

The state stores the block root of the latest `SLOTS_PER_HISTORICAL_ROOT` blocks - storing one state per that many blocks allows verifying the integrity of the blocks easily against the given state, and ensures that all block and state root information remains available, for example to validate states and blocks against `historical_roots`.

## Why include the state at all?

This is a tradeoff between being able to access state data such as validator keys and balances directly vs and recreating it by applying each block one by one from from genesis. Given an era file, you can always start processing the chain from there onwards.

## Why the weird file name?

Historical roots for the entire beacon chain history are stored in the state - thus, with a recent state one can quickly judge if an era file is part of the same history - this is useful for example when performing checkpoint sync.

The genesis era file uses the genesis validators root for two reasons: it allows disambiguating otherwise similar chains and the genesis state does not yet have a historical root to use.

The era numbers are zero-filled so that they trivially can be sorted - 5 digits is enough for 99999 eras or ~312 years

## How long is an era?

An era is typically 8192 slots, or roughly 27.3 hours - a bit more than a day.

## What happens after the merge?

Era files will store execution block contents, but not execution states (these are too large) - a full era history thus gives the full ethereum history from the merge onwards, for convenient cold storage.

## What is a "era state" and why use it?

The state transition function in ethereum does 3 things: slot processing, epoch processing and block processing, in that order. In particular, the slot and epoch processing is done for every slot and epoch, but the block processing may be skipped. When epoch processing is done, all the epoch-related fields in the state have been written, and a new epoch can begin - it's thus reasonable to say that the epoch processing is the last thing that happens in an epoch and the block processing happens in the context of the new epoch.

Storing the "era state" without the block applied means that any block from the new epoch can be applied to it - if two histories exist, one that skips the first block in the epoch and one that includes it, one can use the same era state in both cases.

One downside is that future blocks will store the state root of the "era state" with the block applied, making it slightly harder to verify that the state in a given era file is part of a particular history.

TODO: consider workarounds for the above point - one can state-transition to find the right state root, but that increases verification requirements significantly.
