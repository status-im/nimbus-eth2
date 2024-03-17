import ./forks

func get_epoch_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, epoch: Epoch): CookedSig = default(CookedSig)

func compute_block_signing_root*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    blck: Eth2Digest | SomeForkyBeaconBlock | BeaconBlockHeader): Eth2Digest = default(Eth2Digest)

func get_block_signature*(
    fork: Fork, genesis_validators_root: Eth2Digest, slot: Slot,
    root: Eth2Digest): CookedSig = default(CookedSig)

func get_deposit_signature*(preset: RuntimeConfig,
                            deposit: DepositData): CookedSig = default(CookedSig)

func get_deposit_signature*(message: DepositMessage, version: Version): CookedSig = default(CookedSig)
