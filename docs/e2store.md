# Introduction

The `e2store` (extension: `.e2s`) is a simple linear [Type-Length-Value](https://en.wikipedia.org/wiki/Type-length-value) file for long-term cold storage of arbitrary items typically found in Ethereum. Entries encoded using serialization techniques used in ethereum 2 in general: SSZ, varint, snappy.

# General structure

`e2s` files consist of repeated type-length-value records. Each record is variable-length, and unknown records can easily be skipped. In particular, `e2s` files are designed to:

* allow trivial implementations that are easy to audit
* allow append-only implementations
* allow future record types to be added, such as when the chain forks

The type and length are encoded in an 8-byte header which is directly followed by data.

The header corresponds to an SSZ object defined as such:

```python
class Header(Container):
    type: Vector[byte, 2]
    length: uint32
    reserved: uint16
```

The `length` is the length of the data that follows the header, not including the length of the header itself.

The `reserved` field must be set to `0`.

For example, an entry with header type `[0x22, 0x32]`, length `4` and the content `[0x01, 0x02, 0x03, 0x04]` will be stored as the byte sequence `[0x22, 0x32, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]`.

`.e2s` files may freely be concatenated, and may contain out-of-order records.

Types that have the high bit in the first byte set (those in the range `[0x80-0xff]`) are application and/or vendor specific - other types are reserved for future versions of this specification.

Records may be traversed without any further out-of-band knowledge, but in order to interpret contents the decode must know the preset and runtime configuration of the network.

## Reading

The following python code can be used to read an `e2` file:

```python
import sys, struct

def read_entry(f):
  header = f.read(8)
  if not header: return None

  typ = header[0:2] # 2 bytes of type
  dlen = struct.unpack("<I", header[2:6])[0] # 4 bytes of unsigned little-endian length

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

`e2s` files are written record-by-record starting with a version record. Files may be concatenated freely, meaning that the version record may appear multiple times in the file and a single file may have multiple versions.

The version record is used to introduce backwards-incompatible changes to the file format - readers should not attempt to read unknown versions.

When splitting a multi-record file, a version record must appear first in each of the new files.

# Known types

## Version

```
type: [0x65, 0x32]
```

The `version` type must be the first record in the file. Its type is `[0x65, 0x32]` (`e2` in ascii) and the length of its data field is always 0, thus the first 8 bytes of an `e2s` file are always `[0x65, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`.

When a new version record is encountered, it applies to all records following the version entry - this can happen when two e2s files are concatenated.

## CompressedSignedBeaconBlock

```
type: [0x01, 0x00]
data: snappyFramed(ssz(SignedBeaconBlock))
```

`CompressedSignedBeackBlock` contain `SignedBeaconBlock` objects encoded using `SSZ` then compressed using the snappy [framing format](https://github.com/google/snappy/blob/master/framing_format.txt).

The encoding matches that of the `BeaconBlocksByRoot` and `BeaconBlocksByRange` requests from the p2p specification.

The fork and thus the exact format of the `SignedBeaconBlock` should be derived from the `slot`.

## CompressedBeaconState

```
type: [0x02, 0x00]
data: snappyFramed(ssz(BeaconState))
```

`CompressedBeaconState` entries contain a `BeaconState`, and are encoded the same way as `CompressedSignedBeaconBlock`.

The fork and thus the exact format of the `BeaconState` should be derived from the `slot`.

## Empty

```
type: [0x00, 0x00]
```

The `Empty` type contains no data, but may have a length. The corresponding amount of data should be skipped while reading the file.

## SlotIndex

```
type: [0x69, 0x32]
data: starting-slot | index | index | index ... | count
```

`SlotIndex` records store offsets, in bytes, from the beginning of the index record to the beginning of the corresponding data at that slot. An offset of `0` indicates that no data is present for the given slot.

Each entry in the slot index is a fixed-length 8-byte two's complement signed integer in little-endian, meaning that the entry for slot `N` can be found at index `(N * 8) + 16` in the index. The length of a `SlotIndex` record can be computed as `count * 8 + 24` - one entry for every slot and 8 bytes each for type header, starting slot and count. In particular, knowing where the slot index ends allows finding its beginning as well.

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

`.era` files are special instances of `.e2s` files that follow a more strict content format optimised for reading and long-term storage and distribution.

Era files contain groups consisting of a state and the blocks that led up to it, limited to `SLOTS_PER_HISTORICAL_ROOT` slots each.

In examples, we assume the mainnet configuration: `SLOTS_PER_HISTORICAL_ROOT == 8192`.

Each era is identified by when it ends. Thus, the genesis era is era `0`, followed by era `1` which ends when slot `8192` has been processed.

## File name

`.era` file names follow a simple convention: `<config-name>-<era-number>-<era-count>-<short-historical-root>.era`:

* `config-name` is the `CONFIG_NAME` field of the runtime configation (`mainnet`, `prater`, `sepolia`, `holesky`, etc)
* `era-number` is the number of the _first_ era stored in the file - for example, the genesis era file has number 0 - as a 5-digit 0-filled decimal integer
* `short-era-root` is the first 4 bytes of the last historical root in the _last_ state in the era file, lower-case hex-encoded (8 characters), except the genesis era which instead uses the `genesis_validators_root` field from the genesis state.
  * The root is available as `state.historical_roots[era - 1]` except for genesis, which is `state.genesis_validators_root`
  * Post-Capella, the root must be computed from `state.historical_summaries[era - state.historical_roots.len - 1]`

Era files with multiple eras use the era number of the lowest era stored in the file, and the root of the highest era.

An era file containing the mainnet genesis is thus named `mainnet-00000-4b363db9.era`, and the era after that `mainnet-00001-40cf2f3c.era`.

## Structure

An `.era` file is structured in the following way:

```
era := group+
group := Version | block* | era-state | other-entries* | slot-index(block)? | slot-index(state)
block := CompressedSignedBeaconBlock
era-state := CompressedBeaconState
```

The `block` entries of a group include all blocks leading up to the era transition in slot order. For example, the group representing era `1` contains blocks from slot `0` up to and including block `8191`. Empty slots are skipped.

The `era-state` is the state in the era transition slot. The genesis group contains only the genesis state but no blocks. For example, the group representing era `1` contains the canonical state of slot `8192`.

`slot-index(block)` is a `SlotIndex` entry with `count = SLOTS_PER_HISTORICAL_ROOT` for the `CompressedSignedBeaconBlock` entries in that era, pointing out the offsets of each block in the era. It is omitted for the genesis era.

`slot-index(state)` is a `SlotIndex` entry with `count = 1` for the `CompressedBeaconState` entry of that era, pointing out the offset where the state entry begins.

`other-entries` is an extension point for future record types in the era file. The positioning of these allows the indices to continue to be looked up from the back of the group.

The structure of the era file gives it the following properties:

* the indices at the end are fixed-length: they can be used to discover the beginning of an era if the end of it is known
* the start slot field of the state slot index idenfifies which era the group pertains to
* the state in the era file is the end state after having applied all the blocks in the era and, if applicable, the block at the first slot - the `block_roots` entries in the state can be used to discover the digest of the blocks - either to verify the intergrity of the era file or to quickly load block roots without computing them.
* each group in the era file is full, indendent era file - groups can freely be split and combined

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

## Verifying era files

To verify the internal consistency of an era file, the following checks should be made to verify that an era file is valid for a given network:

* each group follows the given structure of era files with regards to blocks, states and their indices
  * offsets within indices must point to entries of the correct kind that can be decompressed and deserialized
  * era file readers must be prepared to handle malicious inputs, including out-of-range offsets, invalid length prefixes and other trivial errors
  * unknown record types should be ignored, but it is recommended that verifiers report their size and tag
* the state is loadable and consistent with the given runtime configuration
* the root of each block in the era file matches that of `state.block_roots` - if a slot is empty according to the block index, this should be confirmed by verifying that
  `state.get_block_root_at_slot(empty_slot - 1) == state.get_block_root_at_slot(empty_slot)` except for the first slot of the era which, if possible, should be verified against `era - 1`
  * the genesis era file does not have any blocks
* the signature of each block can be verified by the keys in the given state (or any newer state).

Extended verification consists of verifying a list of era files against a particular history anchored in a checkpoint or a head block. Verification starts from a well-known finalized checkpoint for a slot within the era, using `anchor_state_root = checkpoint_state.state_roots[0]` as anchor and walking the era files as a linked list.

For each era file:

* verify that `hash_tree_root(state) == anchor_state_root`
  * this anchors the era in a particular history, starting from the given state root - the state root is available from any state within the anchor era.
* verify the internal consistency of the era, as above
* set `anchor_state_root == state.state_roots[0]`

# FAQ

## Why snappy (sz) framed compression?

* The networking protocol uses snappy framed compression, avoiding the need to re-compress data to serve blocks
* Each entry in the file can be decompressed independently (and partially!)
* It's fast and compresses decently - some compression stats for the first 100 eras:
  * Uncompressed: 8.4gb
  * `sz`-compressed: 4.7gb
  * `xz`-compressed: 3.8gb

## Why `SLOTS_PER_HISTORICAL_ROOT` blocks per state?

The state stores the block root of the latest `SLOTS_PER_HISTORICAL_ROOT` blocks - storing one state per that many blocks allows verifying the integrity of the blocks easily against the given state, and ensures that all block and state root information remains available, for example to validate states and blocks against `historical_roots`.

## Why include the state at all?

This is a tradeoff between being able to access state data such as validator keys and balances directly vs and recreating it by applying each block one by one from from genesis. Given an era file, it is possible to start processing the chain from there onwards.

## Why the weird file name?

Historical roots for the entire beacon chain history are stored in the state - thus, with a recent state one can quickly judge if an era file is part of the same history - this is useful for example when performing checkpoint sync.

The genesis era file uses the genesis validators root for two reasons: it allows disambiguating otherwise similar chains and the genesis state does not yet have a historical root to use.

The era numbers are zero-filled so that they trivially can be sorted - 5 digits is enough for 99999 eras or ~312 years.

Using the first era number and the last root allows a reading application to quickly determine the range of data in the era file.

## How long is an era?

An era is typically `8192` slots (in the mainnet configuration), or roughly 27.3 hours.

## What happens after the merge?

Era files will store execution block contents, but not execution states (these are too large) - a full era history thus gives the full ethereum history from the merge onwards for convenient cold storage. Work is underway to similarly cover the rest of history.

## Which state should be stored in the era file?

The state transition function in ethereum does 3 things: slot processing, epoch processing and block processing, in that order. In particular, the slot and epoch processing is done for every slot and epoch, but the block processing may be skipped. When epoch processing is done, all the epoch-related fields in the state have been written, and a new epoch can begin - it's thus reasonable to say that the epoch processing is the last thing that happens in an epoch and the block processing happens in the context of the new epoch.

The protocol favours the state root with the block applied, as both `BeaconState.state_roots` and `BeaconBlock.state_root`, thus era files follow suit.

The alternative that was considered is to store the state without the block applied - this has several advantages:

* the era file to be used both for future histories with and without a block at the beginning
* no special case is needed when replaying blocks from era files - all are applied in the order they appear in the era file

In the end though, the applied block state is used throughout in the protocol - given a block, the state root in the block is computed with the data from the block applied and this later gets stored in `state_roots` which forms the basis for `historical_roots`. In API:s such as the beacon API, the canonical state root of a slot is the state with the block of that slot applied, if it is part of the canonical history given by the head.

## How can block roots be accessed without computing them?

Each era file contains a full `BeaconState` object whose `block_roots` field corresponds to the block contents of the file. The easiest way to access the roots is to read the "header" of the `BeaconState` without reading all fields.

## Why is length `uint32`?

Offsets in `SSZ` are `uint32` thus from a practical point of view, any one SSZ object may generally not exceed that size.

A future entry type can introduce chunking should larger entries be needed, or spill the remaining size bytes into `reserved`, effectively turning the encoding of the length into a fictive `uint48` type.
