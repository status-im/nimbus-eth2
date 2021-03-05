import sys, struct

def read_e2store(name):
  with open(name, "rb") as f:
    header = f.read(8)
    typ = header[0:2] # First 2 bytes for type

    if typ != b"e2":
      raise RuntimeError("this is not an e2store file")

    while True:
      header = f.read(8) # Header is 8 bytes
      if not header: break

      typ = header[0:2] # First 2 bytes for type
      dlen = struct.unpack("<q", header[2:8] + b"\0\0")[0] # 6 bytes of little-endian length

      data = f.read(dlen)
      if len(data) != dlen: # Don't trust the given length, specially when pre-allocating
        raise RuntimeError("File is missing data")

      if typ == b"i2":
        raise RuntimeError("Cannot switch to index mode")
      elif typ == b"e2":
        pass # Ignore extra headers

      yield (typ, data)

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

name = sys.argv[1]
if name.endswith(".e2i"):
  print(find_offset(name, int(sys.argv[2])))
else:
  for typ, data in read_e2store(name):
    print("typ", typ, "data", len(data))
