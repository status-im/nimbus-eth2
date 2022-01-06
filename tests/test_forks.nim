import
  unittest2,
  stew/byteutils,
  ../beacon_chain/spec/[forks, helpers],
  ../beacon_chain/spec/datatypes/[phase0, altair, merge]

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

suite "Forked SSZ readers":
  var
    cfg = defaultRuntimeConfig

  cfg.ALTAIR_FORK_EPOCH = Epoch(1)
  cfg.MERGE_FORK_EPOCH = Epoch(2)

  test "load phase0 state":
    testHashedBeaconState(phase0.BeaconState, 0.Slot)

    expect(SszError):
      testHashedBeaconState(altair.BeaconState, 0.Slot)
    expect(SszError):
      testHashedBeaconState(merge.BeaconState, 0.Slot)

  test "load altair state":
    testHashedBeaconState(altair.BeaconState, cfg.ALTAIR_FORK_EPOCH.compute_start_slot_at_epoch)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState, cfg.ALTAIR_FORK_EPOCH.compute_start_slot_at_epoch)
    expect(SszError):
      testHashedBeaconState(merge.BeaconState, cfg.ALTAIR_FORK_EPOCH.compute_start_slot_at_epoch)

  test "load merge state":
    testHashedBeaconState(merge.BeaconState, cfg.MERGE_FORK_EPOCH.compute_start_slot_at_epoch)

    expect(SszError):
      testHashedBeaconState(phase0.BeaconState, cfg.MERGE_FORK_EPOCH.compute_start_slot_at_epoch)
    expect(SszError):
      testHashedBeaconState(altair.BeaconState, cfg.MERGE_FORK_EPOCH.compute_start_slot_at_epoch)

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
      testTrustedSignedBeaconBlock(merge.TrustedSignedBeaconBlock, 0.Slot)

  test "load altair block":
    testTrustedSignedBeaconBlock(altair.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.compute_start_slot_at_epoch)
    expect(SszError):
      testTrustedSignedBeaconBlock(phase0.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.compute_start_slot_at_epoch)
    expect(SszError):
      testTrustedSignedBeaconBlock(merge.TrustedSignedBeaconBlock, cfg.ALTAIR_FORK_EPOCH.compute_start_slot_at_epoch)

  test "load merge block":
    testTrustedSignedBeaconBlock(merge.TrustedSignedBeaconBlock, cfg.MERGE_FORK_EPOCH.compute_start_slot_at_epoch)

    expect(SszError):
      testTrustedSignedBeaconBlock(phase0.TrustedSignedBeaconBlock, cfg.MERGE_FORK_EPOCH.compute_start_slot_at_epoch)
    expect(SszError):
      testTrustedSignedBeaconBlock(altair.TrustedSignedBeaconBlock, cfg.MERGE_FORK_EPOCH.compute_start_slot_at_epoch)

  test "should raise on unknown data":
    let
      bytes = SSZ.encode(AttestationData())
    expect(SszError):
      discard newClone(readSszForkedSignedBeaconBlock(cfg, bytes))
