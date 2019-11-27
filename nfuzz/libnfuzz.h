#ifndef __LIBNFUZZ_H__
#define __LIBNFUZZ_H__

#ifdef __cplusplus
extern "C" {
#endif

void NimMain();

bool nfuzz_block(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size);
bool nfuzz_attestation(uint8_t* input_ptr, size_t input_size,
  uint8_t* output_ptr, size_t* output_size);
void nfuzz_shuffle(uint8_t* seed_ptr, uint64_t* output_ptr, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif //__LIBNFUZZ_H__
