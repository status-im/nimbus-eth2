import memfiles, streams, os

type
    DataProc* = proc(val: openArray[byte])

    PersistentStore* = object
        storage*: string
        indices*: string


const STORAGE = "storage"
const INDICES = "indices"
proc createFiles(names: array[2, string]) =
    for name in names:
        let fs = newFileStream(name, fmWrite);
        fs.close() 

proc init*(T: type PersistentStore): PersistentStore =
    createFiles([STORAGE, INDICES])
    T(storage: STORAGE, indices: INDICES)

proc append(fn: string, data: openArray[byte]) =
    let fs = newFileStream(fn, fmAppend)
    fs.writeData(unsafeAddr(data), len(data))
    fs.close()

proc getSize*(fn: string): uint64 =
    uint64 getfileSize fn

proc put*(db: PersistentStore, key,val: openArray[byte]) =
    db.indices.append(key)
    db.storage.append(val)

# TODO figure it out how to make best use of memfiles 
proc read*(fn: string, offset, len: uint64, onData: DataProc) =
    var fs = newMemMapFileStream(fn, fmRead)
    var buffer = newSeq[byte](len)
    fs.setPosition(int(offset))
    discard fs.readData(addr(buffer[0]), int(len))
    fs.close()
    onData(buffer)
