    .section .rodata

# name_data = start of data
# name_end = end of data (without alignment)
# name = 64-bit pointer to data
# name_size = 64-bit length in bytes

eth2_mainnet_genesis_data:
    .incbin "../../vendor/eth2-networks/shared/mainnet/genesis.ssz"
eth2_mainnet_genesis_end:
    .global eth2_mainnet_genesis
    .type   eth2_mainnet_genesis, @object
    .balign  8
eth2_mainnet_genesis:
    .quad eth2_mainnet_genesis_data
    .global eth2_mainnet_genesis_size
    .type   eth2_mainnet_genesis_size, @object
eth2_mainnet_genesis_size:
    .quad    eth2_mainnet_genesis_end - eth2_mainnet_genesis_data


eth2_goerli_genesis_data:
    .incbin "../../vendor/eth2-networks/shared/prater/genesis.ssz"
eth2_goerli_genesis_end:
    .global eth2_goerli_genesis
    .type   eth2_goerli_genesis, @object
    .balign  8
eth2_goerli_genesis:
    .quad eth2_goerli_genesis_data
    .global eth2_goerli_genesis_size
    .type   eth2_goerli_genesis_size, @object
eth2_goerli_genesis_size:
    .quad    eth2_goerli_genesis_end - eth2_goerli_genesis_data


eth2_sepolia_genesis_data:
    .incbin "../../vendor/sepolia/bepolia/genesis.ssz"
eth2_sepolia_genesis_end:
    .global eth2_sepolia_genesis
    .type   eth2_sepolia_genesis, @object
    .balign  8
eth2_sepolia_genesis:
    .quad eth2_sepolia_genesis_data
    .global eth2_sepolia_genesis_size
    .type   eth2_sepolia_genesis_size, @object
eth2_sepolia_genesis_size:
    .quad    eth2_sepolia_genesis_end - eth2_sepolia_genesis_data
