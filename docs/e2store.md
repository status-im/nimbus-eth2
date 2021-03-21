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

with open(sys.argv[1], "rb") as f:
  header = f.read(8)
  typ = header[0:2] # First 2 bytes for type

  if typ != b"e2":
    raise RuntimeError("this is not an e2store file")

  while True:
    header = f.read(8) # Header is 8 bytes
    if not header: break

    typ = header[0:2] # First 2 bytes for type
    dlen = struct.unpack("<q", header[2:8] + b"\0\0")[0] # 6 bytes of little-endian length

    print("typ:", "".join("{:02x}".format(x) for x in typ), "len:", dlen)

    data = f.read(dlen)
    if len(data) != dlen: # Don't trust the given length, specially when pre-allocating
      print("Missing data", len(data), dlen)
      break

    if typ == b"i2":
      print("Index header")
      break
    elif typ == b"e2":
      print("e2 header") # May appear
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

# Slot Index files

Index files are files that store indices to linear histories of entries. They consist of offsets that point the the beginning of the corresponding record. Index files start with an 8-byte header and a starting offset followed by a series of `uint64` encoded as little endian bytes. An index of 0 idicates that there is no data for the given slot.

Each entry in the slot index is fixed-length, meaning that the entry for slot `N` can be found at index `(N * 8) + 16` in the index file. Index files only support linear histories.

By convention, slot index files have the name `.e2i`.

```
header | starting-slot | index | index | index ...
```

## IndexVersion

```
type: [0x69, 0x32]
```

The `version` header of an index file consists of the bytes `[0x69, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`.

## Reading

```python
def find_offset(name, slot):
  # Find the offset of a given slot
  with open(name, "rb") as f:
    header = f.read(8)
    typ = header[0:2] # First 2 bytes for type

    if typ != b"i2":
      raise RuntimeError("this is not an e2store file")

    start_slot = struct.unpack("<q", f.read(8))[0]

    f.seek(8 * (slot - start_slot) + 16)

    return struct.unpack("<q", f.read(8))[0]

```

# Era files

`.era` files are special instances of `.e2s` files that follow a more strict content format optimised for reading and long-term storage and distribution. Era files contain groups consisting of a state and the blocks that led up to it, limited to `SLOTS_PER_HISTORICAL_ROOT` slots each, allowing quick verification of the data contained in the file.

Each era is identified by when it ends. Thus, the genesis era is era 0, followed by era 1 which ends before slot 8192 etc.

`.era` files MAY follow a simple naming convention: `eth2-<network>-<era-number>-<era-count>.era` with era and count hex-encoded to 8 digits.

An `.era` file is structured in the following way:

```
era := group+
group := canonical-state | blocks*
```

The `canonical-state` is the state of the slot that immediately follows the end of the era without applying blocks from the next era. For example, for the era that covers the first 8192 slots will have all blocks applied up to slot 8191 and will `process_slots` up to 8192. The genesis group contains only the genesis state but no blocks.

Era files place the state first for a number of reasons: the state is then guaranteed to contain all public keys and block roots needed to verify the blocks in the file. A special case is the genesis era file - this file contains only the genesis state.
