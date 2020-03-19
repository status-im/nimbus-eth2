import streams, options, 
    ../beacon_chain/[ssz],
    ../beacon_chain/ssz/[bytes_reader, navigator],
    ../beacon_chain/spec/[datatypes, digest, helpers, validator]


const OFFSET_SIZE = 8
const LENGTH_SIZE = 8
const STORAGE = "storage"
const INDEXES = "indexes"

type
    ColdStorage* = ref object
        storage* : FileRef
        indexes* : FileRef
        headIndex*: Index

    FileRef* = object
        name*: string

    Index* = object
        slot*: Slot
        word*: Word
    
    Word = object
        offset: int
        length: int
    
    DataProc* = proc(val: openArray[byte])


proc getWord*(slot: Slot): Word = 
    const idxSize = OFFSET_SIZE + LENGTH_SIZE
    return Word(offset: int(slot) * idxSize, length: idxSize)


proc append(file: FileRef, data: seq[byte]) =
    let fs = newFileStream(file.name, fmAppend)
    fs.write(cast[string](data))
    fs.close()

proc read(file: FileRef, word: Word): seq[byte] =
    let fs = newFileStream(file.name, fmRead)
    var buffer = newSeq[byte](word.length)
    fs.setPosition(word.offset)
    let read = fs.readData(addr(buffer[0]), word.length)
    assert read == word.length
    fs.close()
    buffer

func lenghtSum(words: seq[Word]): int =
    for w in words:
        result += w.length

proc read(file: FileRef, words: seq[Word]): seq[byte] =
    let totalLength = lenghtSum(words)
    var buff = newSeq[byte](totalLength)
    var fs = newFileStream(file.name, fmRead)
    var prevPtr = 0
    for w in words:
        fs.setPosition(w.offset)
        let read = fs.readData(addr(buff[prevPtr]), w.length)
        prevPtr += read
    fs.close()
    return buff

proc createFiles(names: array[2, string]) =
    for name in names:
        let fs = newFileStream(name, fmWrite);
        fs.close() 

proc init*(T: type ColdStorage): ColdStorage =
    createFiles([STORAGE, INDEXES])
    T(storage: FileRef(name: STORAGE),
    indexes: FileRef(name: INDEXES), 
    headIndex:Index(slot: Slot(uint64.high), word:Word(offset: 0 ,length:0)))


proc put*(db: ColdStorage, slot: Slot, blckData: seq[byte]) =
    let off = db.headIndex.word.offset
    let idx = db.headIndex.word.length 
    let availableOffset = off + idx
    var idxData = SSZ.encode(Slot(availableOffset)) & SSZ.encode(Slot(len(blckData)))
    var emptIdxData = newSeq[byte](0)
    if not (db.headIndex.slot + 1 == slot):
        #We're must consider all the slots with no blocks in the index file  
        let diff = slot - db.headIndex.slot        
        for i in 0..diff - 2:
            emptIdxData.add(SSZ.encode(Slot(off)) & SSZ.encode(Slot(idx)))

    db.indexes.append(emptIdxData & idxData)
    db.storage.append(blckData)
    db.headIndex = Index(slot:slot, word: Word(offset: availableOffset ,length: len(blckData)))

proc put*(db: ColdStorage, signedBlock: SignedBeaconBlock) =
    let blck = SSZ.encode(signedBlock)
    db.put(signedBlock.message.slot, blck) 

proc parseWord(rawData: openArray[byte]): seq[Word] =
    var wrds = newSeq[Word](0)
    var j = 0
    while j < len(rawData):
        let off = SSZ.decode(rawData[j..j + OFFSET_SIZE - 1], uint64)
        let lgt = SSZ.decode(rawData[j + OFFSET_SIZE..j + OFFSET_SIZE + LENGTH_SIZE - 1], uint64)
        wrds.add(Word(offset: int(off), length: int(lgt)))
        j += (OFFSET_SIZE + LENGTH_SIZE)
    wrds

proc getIndex(db: ColdStorage, word: Word): Word =
    let raw = db.indexes.read(word)
    parseWord(raw)[0]

proc get*(db: ColdStorage, slot: Slot, ondata: DataProc): bool =
    let indexWord = getWord(slot)
    let idx = db.getIndex(indexWord)
    let raw = db.storage.read(idx)
    ondata(raw)
    return true

proc get*(db: ColdStorage, slot: Slot): Option[SignedBeaconBlock] =
    var slt = slot
    if(slot > db.headIndex.slot):
        slt = db.headIndex.slot
    
    var blck: Option[SignedBeaconBlock]
    let indexWord = getWord(slt)
    let idx = db.getIndex(indexWord)
    let raw = db.storage.read(idx)
    try:
        blck = some(SSZ.decode(raw, SignedBeaconBlock))
    except SerializationError:
        echo "Error decoding block" 
    blck


proc get*(db: ColdStorage, startingSlot: Slot, count: int, step: int): seq[SignedBeaconBlock] =
    var i = 0
    var slot = startingSlot
    var indxsWords = newSeq[Word](0)
    while i < count or slot <= db.headIndex.slot:
        indxsWords.add(getWord(slot))
        slot += Slot(step)
        i += 1

    let rawIndexes = db.indexes.read(indxsWords)
    let wrds = parseWord(rawIndexes)
    let blckData = db.storage.read(wrds)
    var blcks = newSeq[SignedBeaconBlock](0)
    var str = 0
    for w in wrds:
        try:
            var blck: Option[SignedBeaconBlock]  
            blck = some(SSZ.decode(blckData[str.. str + w.length - 1], SignedBeaconBlock))
            blcks.add(blck.get)
        except SerializationError:
            echo "Error decoding block"
        
        str += w.length
    blcks

# proc get*[T](db: ColdStorage, slot: Slot, nav: SszDelayedNavigator[T]): auto =
#     let indexWord = getWord(slot)
#     let idx = db.getIndex(indexWord)
#     nav.get(idx.offset, idx.length, proc(off:int):int =
#         let raw = db.storage.read(Word(offset:off, length: 4))
#         int fromSszBytes(uint32,raw)
#     )