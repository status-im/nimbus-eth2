import
  ./datatypes/phase0, ./helpers, ./eth2_merkleization

func get_epoch_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch): CookedSig = default(CookedSig)

func compute_block_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    blck: Eth2Digest | SomeForkyBeaconBlock | BeaconBlockHeader): Eth2Digest =
  let
    epoch = epoch(slot)
    domain = get_domain(
      fork, DOMAIN_BEACON_PROPOSER, epoch, genesis_validators_root)
  compute_signing_root(blck, domain)

func get_block_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    root: Eth2Digest): CookedSig = default(CookedSig)

func get_deposit_signature*(preset: RuntimeConfig,
                            deposit: DepositData): CookedSig = default(CookedSig)

func get_deposit_signature*(message: DepositMessage, version: Version): CookedSig = default(CookedSig)
