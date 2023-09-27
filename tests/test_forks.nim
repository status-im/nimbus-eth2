{.used.}

import
  unittest2,
  ../beacon_chain/spec/forks

template testHashedBeaconState(T: type, s: Slot) =
  let state = (ref T)()
  state[].slot = s
  let
    bytes = SSZ.encode(state[])
    forked = (ref ForkedHashedBeaconState)()

  forked[] = readSszForkedHashedBeaconState(cfg, bytes)

  check:
    forked.kind == T.kind

template testTrustedSignedBeaconBlock(T: type, s: Slot) =
  let blck = (ref T)()
  blck[].message.slot = s
  let
    bytes = SSZ.encode(blck[])
    forked = (ref ForkedSignedBeaconBlock)()

  forked[] = readSszForkedSignedBeaconBlock(cfg, bytes)

  check:
    forked.kind == T.kind

suite "Type helpers":
  test "BeaconBlockType":
    check:
      BeaconBlockType(ConsensusFork.Phase0) is phase0.BeaconBlock
      BeaconBlockType(ConsensusFork.Altair) is altair.BeaconBlock
      BeaconBlockType(ConsensusFork.Bellatrix) is bellatrix.BeaconBlock
      BeaconBlockType(ConsensusFork.Capella) is capella.BeaconBlock
      BeaconBlockType(ConsensusFork.Deneb) is deneb.BeaconBlock
      BeaconBlockBodyType(ConsensusFork.Phase0) is phase0.BeaconBlockBody
      BeaconBlockBodyType(ConsensusFork.Altair) is altair.BeaconBlockBody
      BeaconBlockBodyType(ConsensusFork.Bellatrix) is bellatrix.BeaconBlockBody
      BeaconBlockBodyType(ConsensusFork.Capella) is capella.BeaconBlockBody
      BeaconBlockBodyType(ConsensusFork.Deneb) is deneb.BeaconBlockBody

suite "Forked SSZ readers":
  let cfg = block:
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = Epoch(1)
    cfg.BELLATRIX_FORK_EPOCH = Epoch(2)
    cfg.CAPELLA_FORK_EPOCH = Epoch(3)
    cfg.DENEB_FORK_EPOCH = Epoch(4)
    cfg

  test "load phase0 state":
    testHashedBeaconState(phase0.BeaconState,      0.Slot)

    expect(SszError):
      testHashedBeaconState(altair.BeaconState,    0.Slot)
    expect(SszError):
      testHashedBeaconState(bellatrix.BeaconState, 0.Slot)
    expect(SszError):
      testHashedBeaconState(capella.BeaconState,   0.Slot)
    expect(SszError):
      testHashedBeaconState(deneb.BeaconState,     0.Slot)

  test "load altair state":
    testHashedBeaconState(altair.BeaconState,      cfg.ALTAIR_FORK_EPOCH.start_slot)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState,    cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(bellatrix.BeaconState, cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(capella.BeaconState,   cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(deneb.BeaconState,     cfg.ALTAIR_FORK_EPOCH.start_slot)

  test "load bellatrix state":
    testHashedBeaconState(bellatrix.BeaconState,   cfg.BELLATRIX_FORK_EPOCH.start_slot)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState,    cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(altair.BeaconState,    cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(capella.BeaconState,   cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(deneb.BeaconState,     cfg.BELLATRIX_FORK_EPOCH.start_slot)

  test "load capella state":
    testHashedBeaconState(capella.BeaconState,     cfg.CAPELLA_FORK_EPOCH.start_slot)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState,    cfg.CAPELLA_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(altair.BeaconState,    cfg.CAPELLA_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(bellatrix.BeaconState, cfg.CAPELLA_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(deneb.BeaconState,     cfg.CAPELLA_FORK_EPOCH.start_slot)

  test "load deneb state":
    testHashedBeaconState(deneb.BeaconState,        cfg.DENEB_FORK_EPOCH.start_slot)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState,    cfg.DENEB_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(altair.BeaconState,    cfg.DENEB_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(bellatrix.BeaconState, cfg.DENEB_FORK_EPOCH.start_slot)
    expect(SszError):
      testHashedBeaconState(capella.BeaconState,   cfg.DENEB_FORK_EPOCH.start_slot)

  test "should raise on unknown data":
    let
      bytes = SSZ.encode(AttestationData())
    expect(SszError):
      discard newClone(readSszForkedHashedBeaconState(cfg, bytes))

  test "load phase0 block":
    testTrustedSignedBeaconBlock(phase0.TrustedSignedBeaconBlock,      0.Slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(altair.TrustedSignedBeaconBlock,    0.Slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(bellatrix.TrustedSignedBeaconBlock, 0.Slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(capella.TrustedSignedBeaconBlock,   0.Slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(deneb.TrustedSignedBeaconBlock,     0.Slot)

  test "load altair block":
    testTrustedSignedBeaconBlock(
      altair.TrustedSignedBeaconBlock,      cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        phase0.TrustedSignedBeaconBlock,    cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        bellatrix.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        capella.TrustedSignedBeaconBlock,   cfg.ALTAIR_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        deneb.TrustedSignedBeaconBlock,     cfg.ALTAIR_FORK_EPOCH.start_slot)

  test "load bellatrix block":
    testTrustedSignedBeaconBlock(
      bellatrix.TrustedSignedBeaconBlock, cfg.BELLATRIX_FORK_EPOCH.start_slot)

    expect(SszError):
      testTrustedSignedBeaconBlock(
        phase0.TrustedSignedBeaconBlock,  cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        altair.TrustedSignedBeaconBlock,  cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        capella.TrustedSignedBeaconBlock, cfg.BELLATRIX_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        deneb.TrustedSignedBeaconBlock,   cfg.BELLATRIX_FORK_EPOCH.start_slot)

  test "load capella block":
    testTrustedSignedBeaconBlock(
      capella.TrustedSignedBeaconBlock,     cfg.CAPELLA_FORK_EPOCH.start_slot)

    expect(SszError):
      testTrustedSignedBeaconBlock(
        phase0.TrustedSignedBeaconBlock,    cfg.CAPELLA_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        altair.TrustedSignedBeaconBlock,    cfg.CAPELLA_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        bellatrix.TrustedSignedBeaconBlock, cfg.CAPELLA_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        deneb.TrustedSignedBeaconBlock,     cfg.CAPELLA_FORK_EPOCH.start_slot)

  test "load deneb block":
    testTrustedSignedBeaconBlock(
      deneb.TrustedSignedBeaconBlock,       cfg.DENEB_FORK_EPOCH.start_slot)

    expect(SszError):
      testTrustedSignedBeaconBlock(
        phase0.TrustedSignedBeaconBlock,    cfg.DENEB_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        altair.TrustedSignedBeaconBlock,    cfg.DENEB_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        bellatrix.TrustedSignedBeaconBlock, cfg.DENEB_FORK_EPOCH.start_slot)
    expect(SszError):
      testTrustedSignedBeaconBlock(
        capella.TrustedSignedBeaconBlock,   cfg.DENEB_FORK_EPOCH.start_slot)

  test "should raise on unknown data":
    let
      bytes = SSZ.encode(AttestationData())
    expect(SszError):
      discard newClone(readSszForkedSignedBeaconBlock(cfg, bytes))
