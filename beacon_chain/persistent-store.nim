import memfiles, streams

type
    DataProc* = proc(val: openArray[byte])

    ColdStorage* = ref object
    storage* : FileName
    indices* : FileName

    FileName* = object
        name*: static string

template append(fn: FileName, data: openArray[byte]) =
    let fs = newFileStream(fn.name, fmAppend)
    fs.write(cast[string](data))
    fs.close()


proc put*(db: ColdStorage, key,val: openArray[byte]) =
    db.storage.append(val)
    db.storage.append(key)

#TODO substitute to use memfiles 
proc read*(db: ColdStorage, fn: FileName offset, len: uint64, onData: DataProc) =
    let fs = newFileStream(fn.name, fmRead)
    var buffer = newSeq[byte](len)
    fs.setPosition(offset)
    let read = fs.readData(addr(buffer[0]), word.length)
    fs.close()
    onData(buffer)