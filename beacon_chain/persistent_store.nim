import memfiles, streams, os

type
    DataProc* = proc(val: openArray[byte])

    PersistentStore* = object
        storage*: string
        indices*: string


const STORAGE = "storage"
const INDEXES = "indices"
proc createFiles(names: array[2, string]) =
    for name in names:
        let fs = newFileStream(name, fmWrite);
        fs.close() 

proc init*(T: type PersistentStore): PersistentStore =
    createFiles([STORAGE, INDEXES])
    T(storage: STORAGE, indices: INDEXES)

proc append(fn: string, data: seq[byte]) =
    let fs = newFileStream(fn, fmAppend)
    fs.write(cast[string](data))
    fs.close()

proc getSize*(fn: string): uint64 =
    uint64 getfileSize fn

# Using seq[byte] for now because I get bad address errors when using openArray[byte]
proc put*(db: PersistentStore, key,val: seq[byte]) =
    db.storage.append(val)
    db.indices.append(key)

# TODO figure it out how to make best use of memfiles 
proc read*(fn: string, offset, len: uint64, onData: DataProc) =
    var fs = newMemMapFileStream(fn, fmRead)
    var buffer = newSeq[byte](len)
    fs.setPosition(int(offset))
    discard fs.readData(addr(buffer[0]), int(len))
    fs.close()
    onData(buffer)
