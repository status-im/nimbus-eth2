import memfiles, streams, os

type
    DataProc* = proc(val: openArray[byte])

    ColdStorage* = ref object
        storage*: FileName
        indices*: FileName

    FileName* = object
        name*: string

const STORAGE = "storage"
const INDEXES = "indices"
proc createFiles(names: array[2, string]) =
    for name in names:
        let fs = newFileStream(name, fmWrite);
        fs.close() 

proc init*(T: type ColdStorage): ColdStorage =
    createFiles([STORAGE, INDEXES])
    T(storage: FileName(name: STORAGE),
    indices: FileName(name: INDEXES))

template append(fn: FileName, data: seq[byte]) =
    let fs = newFileStream(fn.name, fmAppend)
    fs.write(cast[string](data))
    fs.close()

proc getSize*(fn: FileName): uint64 =
    uint64 getfileSize fn.name

# Using seq[byte] for now because I get bad address errors when using openArray[byte]
proc put*(db: ColdStorage, key,val: seq[byte]) =
    db.storage.append(val)
    db.indices.append(key)

#TODO substitute to use memfiles 
proc read*(fn: FileName, offset, len: uint64, onData: DataProc) =
    let fs = newFileStream(fn.name, fmRead)
    var buffer = newSeq[byte](len)
    fs.setPosition(int(offset))
    let read = fs.readData(addr(buffer[0]), int(len))
    fs.close()
    onData(buffer)
