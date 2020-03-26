import memfiles, streams, os

type
    DataProc* = proc(val: openArray[byte])

    PersistentStore* = object
        fn*: string

const STORAGE = "storage"
proc init*(T: type PersistentStore): PersistentStore =
    let fs = newFileStream(STORAGE, fmWrite);
    fs.close() 
    T(fn: STORAGE)

# Using seq[byte] for now because I get bad address errors when using openArray[byte]
proc put*(db: PersistentStore, data: seq[byte]) =
    let fs = newFileStream(db.fn, fmAppend)
    fs.write(cast[string](data))
    fs.close()

proc getSize*(db: PersistentStore): uint64 =
    uint64 getfileSize db.fn

#TODO figure it out how to make best use of memfiles 
proc readStorage*(db: PersistentStore, offset, len: uint64, onData: DataProc) =
    var fs = newMemMapFileStream(db.fn, fmRead)
    var buffer = newSeq[byte](len)
    fs.setPosition(int(offset))
    discard fs.readData(addr(buffer[0]), int(len))
    fs.close()
    onData(buffer)
