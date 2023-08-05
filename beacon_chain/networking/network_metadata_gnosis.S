# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

#if defined(__APPLE__)
# define cdecl(s) _##s
#else
# define cdecl(s) s
#endif

#if defined(__linux__)
    .section  .note.GNU-stack, "", @progbits
    .section .rodata,"a",@progbits
#elif defined(__APPLE__)
    .section __TEXT,__const
#elif defined(__WIN32__)
    .section .rdata,"dr"
#else
    .text
#endif

# name_data = start of data
# name_end = end of data (without alignment)
# name = 64-bit pointer to data
# name_size = 64-bit length in bytes

gnosis_mainnet_genesis_data:
    .incbin "gnosis-chain-configs/mainnet/genesis.ssz"
gnosis_mainnet_genesis_end:
    .global cdecl(gnosis_mainnet_genesis_size)
    .p2align 3
cdecl(gnosis_mainnet_genesis_size):
    .quad    gnosis_mainnet_genesis_end - gnosis_mainnet_genesis_data

gnosis_chiado_genesis_data:
    .incbin "gnosis-chain-configs/chiado/genesis.ssz"
gnosis_chiado_genesis_end:
    .global cdecl(gnosis_chiado_genesis_size)
    .p2align 3
cdecl(gnosis_chiado_genesis_size):
    .quad    gnosis_chiado_genesis_end - gnosis_chiado_genesis_data

#if defined(__linux__) && (defined(__pie__) || defined(__pic__))
    .section	.data.rel.ro,"aw",@progbits
#elif defined(__APPLE__)
    .section __DATA,__const
#endif

    .global cdecl(gnosis_mainnet_genesis)
    .p2align 3
cdecl(gnosis_mainnet_genesis):
    .quad gnosis_mainnet_genesis_data

    .global cdecl(gnosis_chiado_genesis)
    .p2align 3
cdecl(gnosis_chiado_genesis):
    .quad gnosis_chiado_genesis_data
