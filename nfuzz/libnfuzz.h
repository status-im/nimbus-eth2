#ifndef __LIBNFUZZ_H__
#define __LIBNFUZZ_H__

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize Nim & Garbage Collector. Must be called before anything else
 * of the API. Also, all following calls must come from the same thread as from
 * which this call was done.
 */
void NimMain();

/** Supported fuzzing tests */
bool nfuzz_attestation(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
bool nfuzz_attester_slashing(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
bool nfuzz_block(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
bool nfuzz_block_header(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
bool nfuzz_deposit(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
bool nfuzz_proposer_slashing(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);
bool nfuzz_shuffle(uint8_t* seed_ptr, uint64_t* output_ptr, size_t output_size);
bool nfuzz_voluntary_exit(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size, bool disable_bls);

#ifdef __cplusplus
}
#endif

#endif //__LIBNFUZZ_H__
