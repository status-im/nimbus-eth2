import
  unittest2,
  stew/byteutils,
  ../beacon_chain/spec/[forks, helpers],
  ../beacon_chain/spec/datatypes/[phase0, altair, bellatrix]

{.used.}

template testHashedBeaconState(T: type, s: Slot) =
  let
    state = (ref T)()
  state[].slot = s
  let
    bytes = SSZ.encode(state[])
    forked = (ref ForkedHashedBeaconState)()

  forked[] = readSszForkedHashedBeaconState(cfg, bytes)

  check:
    forked.kind == T.toFork()

template testTrustedSignedBeaconBlock(T: type, s: Slot) =
  let
    blck = (ref T)()

  blck[].message.slot = s

  let
    bytes = SSZ.encode(blck[])
    forked = (ref ForkedSignedBeaconBlock)()

  forked[] = readSszForkedSignedBeaconBlock(cfg, bytes)

  check:
    forked.kind == T.toFork()

suite "Type helpers":
  test "BeaconBlockType":
    check:
      BeaconBlockType(ConsensusFork.Phase0) is phase0.BeaconBlock
      BeaconBlockType(ConsensusFork.Bellatrix) is bellatrix.BeaconBlock
      BeaconBlockBodyType(ConsensusFork.Altair) is altair.BeaconBlockBody
      BeaconBlockBodyType(ConsensusFork.Bellatrix) is bellatrix.BeaconBlockBody

suite "Forked SSZ readers":
  var
    cfg = defaultRuntimeConfig

  cfg.ALTAIR_FORK_EPOCH = Epoch(1)
  cfg.BELLATRIX_FORK_EPOCH = Epoch(2)

  test "load phase0 state":
    testHashedBeaconState(phase0.BeaconState, 0.Slot)

    expect(SszError):
      testHashedBeaconState(altair.BeaconState, 0.Slot)
    expect(SszError):
      testHashedBeaconState(bellatrix.BeaconState, 0.Slot)

  test "load altair state":
    testHashedBeaconState(altair.BeaconState, cfg.ALTAIR_FORK_EPOCH.start_slot)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState, cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(bellatrix.BeaconState, cfg.ALTAIR_FORK_EPOCH.start_slot)

  test "load bellatrix state":
    testHashedBeaconState(bellatrix.BeaconState, cfg.BELLATRIX_FORK_EPOCH.start_slot)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState, cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(altair.BeaconState, cfg.BELLATRIX_FORK_EPOCH.start_slot)

  test "should raise on unknown data":
    let
      bytes = SSZ.encode(AttestationData())
    expect(SszError):
      discard newClone(readSszForkedHashedBeaconState(cfg, bytes))

  test "load phase0 block":
    testTrustedSignedBeaconBlock(phase0.TrustedSignedBeaconBlock, 0.Slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(altair.TrustedSignedBeaconBlock, 0.Slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(bellatrix.TrustedSignedBeaconBlock, 0.Slot)

  test "load altair block":
    testTrustedSignedBeaconBlock(
      altair.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        phase0.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        bellatrix.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.start_slot)

  test "load bellatrix block":
    testTrustedSignedBeaconBlock(
      bellatrix.TrustedSignedBeaconBlock, cfg.BELLATRIX_FORK_EPOCH.start_slot)

    expect(SszError):
      testTrustedSignedBeaconBlock(
        phase0.TrustedSignedBeaconBlock, cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        altair.TrustedSignedBeaconBlock, cfg.BELLATRIX_FORK_EPOCH.start_slot)

  test "should raise on unknown data":
    let
      bytes = SSZ.encode(AttestationData())
    expect(SszError):
      discard newClone(readSszForkedSignedBeaconBlock(cfg, bytes))
