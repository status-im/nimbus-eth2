# Introduction

The `e2store` (extension: `.e2s`) is a simple linear [TLV](https://en.wikipedia.org/wiki/Type-length-value) file for storing arbitrary items typically encoded using serialization techniques used in ethereum 2 in general: SSZ, varint, snappy.

# General structure

`e2s` files consist of repeated type-length-value records. Each record is variable-length, and unknown records can easily be skipped. In particular, `e2s` files are designed to:

* allow trivial implementations that are easy to analyze
* allow append-only implementations
* allow future record types to be added

The type and length are encoded in an 8-byte header which is directly followed by data.

```
record = header | data
header = type | length
type = Vector[byte, 2]
length = Vector[byte, 6]
```

The `length` is the first 6 bytes of a little-endian encoded `uint64`, not including the header itself. For example, the entry with header type `[0x22, 0x32]`, the length `4` and the bytes `[0x01, 0x02, 0x03, 0x04]` will be stored as the byte sequence `[0x22, 0x32, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]`.

## Reading

In a loop, the following pseudocode can be used to read the file:

```
while file.bytesRemaining > 0:
  if file.bytesRemaining < 8:
    abort("Header missing")

  header = read(file, 8)
  type = header[0:2]
  length = fromLittleEndian(header[2:8])

  if file.bytesRemaining < length:
    abort("Not enough data")

  data = read(file, length)

  if type == ...:
    # process the data
  else:
    # Unkown record type, skip
```

## Writing

`e2s` files are linear and append-only. To write a new entry, simply append it to the end of the file. In a separate transaction, the index file may be updated also.

Since the files are append-only, `e2s` files are suitable in particular for finalized blocks only.

# Known types

## Version

```
type: [0x65, 0x32]
data: Vector[byte, 0]
```

The `version` type must be the first record in the file. Its type is `[0x65, 0x32]` (`e2` in ascii) and the length of its data field is always 0, thus the first 8 bytes of an `e2s` file are always `[0x65, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`.

## CompressedSignedBeaconBlock

```
type: [0x01, 0x00]
data: snappyFramed(length-varint | ssz(SignedBeaconBlock))
```

`CompressedSignedBeackBlock` entries are entries whose data field matches the payload of `BeaconBlocksByRange` and `BeaconBlocksByRoot` chunks in the phase0 p2p specification. In particular, the SignedBeaconBlock is serialized using SSZ, prefixed with a varint-length, then compressed using the snappy [framing format](https://github.com/google/snappy/blob/master/framing_format.txt).

# Slot Index files

Index files are files that store indices to linear histories of entries. They consist of offsets that point the the beginning of the corresponding record. Index files start with an 8-byte header, followed by a series of `uint64` encoded as little endian bytes. An index of 0 idicates that there is no data for the given slot.

Each entry in the slot index is fixed-length, meaning that the entry for slot `N` can be found at index `(N * 8) + 8` in the index file. Index files only support linear histories, meaning that the blocks that they point to must have passed finalization.

By convention, slot index files have the name `.e2i`.

```
header | index | index | index ...
```

## IndexVersion

The `version` header of an index file consists of the bytes `[0x69, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]`.

## Index

Index entries are `uint64` offsets, encoded as little-endian, from the beginning of the store file to the corresponding entry.

## Reading

```
  if failed(setpos(indexfile, slot * 8 + 8)):
    abort("no data for the given slot")

  offset = fromLittleEndian(read(indexfile, 8))
  if offset == 0:
    abort("no data for the given slot")

  if failed(setpos(datafile, offset)):
    abort("index file corrupt, data not found at offset")
  header = read(datafile, 8)
  # as above
```
