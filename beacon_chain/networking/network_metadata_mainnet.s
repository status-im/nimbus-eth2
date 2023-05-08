# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

    .data

# name_data = start of data
# name_end = end of data (without alignment)
# name = 64-bit pointer to data
# name_size = 64-bit length in bytes

eth2_mainnet_genesis_data:
    .incbin "../../vendor/eth2-networks/shared/mainnet/genesis.ssz"
eth2_mainnet_genesis_end:
    .global eth2_mainnet_genesis
    .type   eth2_mainnet_genesis, @object
    .p2align 3
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
    .p2align 3
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
    .p2align 3
eth2_sepolia_genesis:
    .quad eth2_sepolia_genesis_data
    .global eth2_sepolia_genesis_size
    .type   eth2_sepolia_genesis_size, @object
eth2_sepolia_genesis_size:
    .quad    eth2_sepolia_genesis_end - eth2_sepolia_genesis_data
