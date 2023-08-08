# CPU Features for Nimbus

This document describes the CPU-specific features and compilation flags that significantly improves Nimbus performance.

We focus on x86-64 and ARMv8 (64 bits).
Given that the major bottleneck of Nimbus is big integer for cryptography, 64-bit architecture improves elliptic curve cryptography processing by ~2x over 32 bits since we can divide the number of low-level assembly operations by half.

_Note: SHA256 isn't improved by 64-bit since it uses 32-bit operations by design_

The major bottlenecks that can be improved by CPU specific instructions are:
- Elliptic curve cryptography for BLS12-381
- SHA256 hashing

## x86

### SSSE3 (Supplemental SSE3)

Intel: Core 2, 2006\
AMD: Bulldozer, 2011\
Flag: `-mssse3`
Configuration: https://github.com/supranational/blst/blob/v0.3.4/build/assembly.S#L3-L6

SSSE3 improves SHA256 computations. SHA256 is used **recursively** to hash all consensus objects and to build a Merkle tree.
Thanks to caching, SHA256 computation speed is mostly relevant only when receiving new blocks and attestations from the network, but state transitions do not depend on it (unlike a naive spec implementation).

**SSSE3 must not be confused with SSE3 from Pentium 3 (2004) and Athlon 64 (2005)**

```
git clone https://github.com/status-im/nim-blscurve
cd nim-blscurve
git submodule update --init
nim c -r -d:danger --passC:"-D__BLST_PORTABLE__" --outdir:build benchmarks/bench_sha256.nim
nim c -r -d:danger --outdir:build benchmarks/bench_sha256.nim
```

Due to tree hashing, hashing 32 bytes is the most important benchmark.

**Without SSSE3**
```
Backend: BLST, mode: 64-bit
==================================================================================

SHA256 - 32B - BLST       4524886.878 ops/s          221 ns/op          660 cycles
SHA256 - 128B - BLST      1776198.934 ops/s          563 ns/op         1689 cycles
SHA256 - 5MB - BLST            70.723 ops/s     14139678 ns/op     42419720 cycles
```
**With SSSE3**

```
Backend: BLST, mode: 64-bit
==================================================================================

SHA256 - 32B - BLST       5376344.086 ops/s          186 ns/op          555 cycles
SHA256 - 128B - BLST      2183406.114 ops/s          458 ns/op         1376 cycles
SHA256 - 5MB - BLST            87.142 ops/s     11475557 ns/op     34427254 cycles
```

### BMI2 & ADX

Intel: Broadwell, 2015\
AMD: Ryzen, 2017\
Configuration: https://github.com/supranational/blst/blob/v0.3.4/build/assembly.S#L18

The MULX instruction (BMI2), ADCX and ADOX (ADX) significantly improves big integer multiplication and squaring.
The speedup is about 20~25% depending on the custom assembly implementation.

All CPUs that support ADX support BMI2.

```
git clone https://github.com/status-im/nim-blscurve
cd nim-blscurve
git submodule update --init
nim c -r -d:danger --hints:off --warnings:off --verbosity:0 --outdir:build benchmarks/bls_signature.nim
nim c -r -d:danger --passC:"-mbmi2 -madx" --hints:off --warnings:off --verbosity:0 --outdir:build benchmarks/bls_signature.nim
```

**Verification** is the bottleneck as it must be done for each block and attestation or aggregate received
and verifying a block requires verifying up to 6 signatures (block proposer, RANDAO, aggregate verifification of attestations, proposer slashings, attester slashings, voluntary exits).
**Signing** can become a bottleneck when a node has many validators.

**Without BMI2 & ADX**
```
Backend: BLST, mode: 64-bit
=============================================================================================================

BLS signature                                           1960.023 ops/s       510198 ns/op      1530624 cycles
BLS verification                                         743.122 ops/s      1345674 ns/op      4037105 cycles
BLS agg verif of 1 msg by 128 pubkeys                    704.634 ops/s      1419176 ns/op      4257591 cycles
BLS verif of 6 msgs by 6 pubkeys                         120.588 ops/s      8292683 ns/op     24878257 cycles
Serial batch verify 6 msgs by 6 pubkeys (with blinding)  218.027 ops/s      4586595 ns/op     13759932 cycles
```

**With BMI2 & ADX**
```
Backend: BLST, mode: 64-bit
=============================================================================================================

BLS signature                                           2550.084 ops/s       392144 ns/op      1176454 cycles
BLS verification                                         930.081 ops/s      1075175 ns/op      3225589 cycles
BLS agg verif of 1 msg by 128 pubkeys                    878.672 ops/s      1138081 ns/op      3414286 cycles
BLS verif of 6 msgs by 6 pubkeys                         154.833 ops/s      6458588 ns/op     19376076 cycles
Serial batch verify 6 msgs by 6 pubkeys (with blinding)  282.562 ops/s      3539046 ns/op     10617328 cycles
```

### SHA-NI

The hardware SHA instructions has NOT been available in Intel consumer hardware until 2021.
AMD has made it available in Zen architecture since 2017.

Intel:
- Rocket Lake (2021)
- Ice Lake (low-power laptops 2018)
- Goldmont (Apollo Lake Pentiums & Celerons 2016, Denverton Atoms 2017)

AMD: Ryzen, 2017\
Flag: `-msha`
Configuration: https://github.com/supranational/blst/blob/v0.3.4/src/sha256.h#L11-L12

On Ryzen, **hardware SHA is 4X faster** than when using SIMD instructions (Table 1, p14).

- SoK: A Performance Evaluation of Cryptographic InstructionSets on Modern Architectures\
  Armando Faz-Hernández, Julio López, Ana Karina D. S. de Oliveira, 2018\
  https://www.lasca.ic.unicamp.br/media/publications/p9-faz-hernandez.pdf

## ARM

32-bit ARM (ARMv6) has a multiplication instruction 32x32 -> 64 called UMULL.

Unfortunately, 64-bit ARM (ARMv8) unlike x86-64 doesn't have a single 64x64 -> 128 multiplication instruction. MUL and UMULH instruction needs to be used for extended precision multiplication.

- Multiprecision Multiplication on ARMv8\
  Zhe Liu, Kimmo Jarvinenadl, Weiqiang Liu, Hwajeong Seo\
  http://arith24.arithsymposium.org/slides/s2-liu.pdf

Concretely, this means that ARMv8 CPUs are impaired compared to x86-64 at equivalent frequency for big integers and cryptography (for example Apple M1).

### Cryptographic extensions

Except for Raspberry Pi, ARMv8 processors support the crypto extensions which include hardware implementation of SHA256.

This is detected via
- `__ARM_FEATURE_CRYPTO` https://github.com/supranational/blst/blob/v0.3.4/src/sha256.h#L14-L15

The compilation flag should be either
- `-mfpu=crypto-neon-fp-armv8`
- or `-march=armv8-a+crypto`

The speedup is expected to be 2x faster than without.\
https://patchwork.kernel.org/project/linux-arm-kernel/patch/20150316154835.GA31336@google.com/
