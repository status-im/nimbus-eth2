import unittest, options,
    ./testutil,
    ../beacon_chain/[cold_storage, ssz],
    ../beacon_chain/spec/[datatypes, crypto, digest, helpers, validator],
    ../beacon_chain/ssz/[navigator, dynamic_navigator],
    ./mocking/[mock_genesis, mock_blocks]



suite "Cold Storage":
    timedTest "sanity blocks":
        
        let gen = initGenesisState(10) 
        var db = init(ColdStorage)        
        
        let
            a0 = SignedBeaconBlock(message: BeaconBlock(slot: GENESIS_SLOT + 0))
            a0r = hash_tree_root(a0.message)
            a1 = SignedBeaconBlock(message:
              BeaconBlock(slot: GENESIS_SLOT + 1, parent_root: a0r))
            a1r = hash_tree_root(a1.message)
            a2 = SignedBeaconBlock(message:
              BeaconBlock(slot: GENESIS_SLOT + 2, parent_root: a1r))
            a2r = hash_tree_root(a2.message)

        db.put(a0)
        db.put(a1)
        db.put(a2)

        check:
            Slot(db.headIndex.slot) == a2.message.slot
        
        let a1ret = db.get(Slot(1)).get()
        let a2ret = db.get(Slot(2)).get()

        check:
            a1ret.message.parent_root == a0r
            a2ret.message.parent_root == a1r

    timedTest "Inserting empty slots":
        let gen = initGenesisState(10) 
        var db = init(ColdStorage)        
        
        let
            a0 = SignedBeaconBlock(message: BeaconBlock(slot: GENESIS_SLOT + 0))
            a0r = hash_tree_root(a0.message)
            a1 = SignedBeaconBlock(message:BeaconBlock(slot: GENESIS_SLOT + 10, parent_root: a0r))

        db.put(a0)
        db.put(a1)

        check:
            db.headIndex.slot == 10

        let a1ret = db.get(Slot(10)).get()

        check:
            a1ret.message.parent_root == a0r

        # Getting empty slot gives you earliest known block
        let a2ret = db.get(Slot(3)).get()
        check:
            a2ret.message.slot == a0.message.slot

    timedTest "Get multiple blocks":
        let gen = initGenesisState(10) 
        var db = init(ColdStorage)        
        
        let
            a0 = SignedBeaconBlock(message: BeaconBlock(slot: GENESIS_SLOT + 0))
            a0r = hash_tree_root(a0.message)
            a1 = SignedBeaconBlock(message:
              BeaconBlock(slot: GENESIS_SLOT + 1, parent_root: a0r))
            a1r = hash_tree_root(a1.message)
            a2 = SignedBeaconBlock(message:
              BeaconBlock(slot: GENESIS_SLOT + 2, parent_root: a1r))
            a2r = hash_tree_root(a2.message)

        db.put(a0)
        db.put(a1)
        db.put(a2)
        let blcks = db.get(Slot(0),3,1)
        check:
            blcks[1].message.parent_root == a0r
            blcks[2].message.parent_root == a1r

    timedTest "Low level syntax":
        let gen = initGenesisState(10) 
        var db = init(ColdStorage)

        let
            a0 = SignedBeaconBlock(message: BeaconBlock(slot: GENESIS_SLOT + 0))
            a0r = hash_tree_root(a0.message)
            a1 = SignedBeaconBlock(message:BeaconBlock(slot: GENESIS_SLOT + 1, parent_root: a0r, state_root: a0r, body: BeaconBlockBody(graffiti: a0r)))

        let encoded = SSZ.encode(a1)
        db.put(a0)
        db.put(Slot(1), encoded)
        
        check:
            db.get(Slot(1), proc(data: openArray[byte])=
                let decoded = SSZ.decode(data, SignedBeaconBlock)
                check decoded.message.parent_root == a0r
            )

    # timedTest "Using mount syntax":
    #     let gen = initGenesisState(10) 
    #     var db = init(ColdStorage)  
    #     let
    #         a0 = SignedBeaconBlock(message: BeaconBlock(slot: GENESIS_SLOT + 0))
    #         a0r = hash_tree_root(a0.message)
    #         a1 = SignedBeaconBlock(message:BeaconBlock(slot: GENESIS_SLOT + 1, parent_root: a0r, state_root: a0r, body: BeaconBlockBody(graffiti: a0r)))

    #     db.put(a0)
    #     db.put(a1)
        
    #     #TODO make this work properly. Missign some navigator stuff
    #     const mounted = sszMount(SignedBeaconBlock)
    #     db.get(Slot(1), mounted.message.parent_root)
        
