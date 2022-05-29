#ifndef AES_MODES_H
#define AES_MODES_H

#include "common.h"

typedef uint8_t* (*CryptoOpFn)(const uint8_t*, const uint8_t*, const size_t, size_t*);

uint8_t* AES_EncryptFileECB(const uint8_t* key,
                       const uint8_t* input,
                       const size_t inputSize,
                       size_t* outputSize);

uint8_t* AES_DecryptFileECB(const uint8_t* key,
                       const uint8_t* input,
                       const size_t inputSize,
                       size_t* outputSize);

uint8_t* AES_EncryptFileCBC(const uint8_t* key,
                       const uint8_t* input,
                       const size_t inputSize,
                       size_t* outputSize);

uint8_t* AES_DecryptFileCBC(const uint8_t* key,
                       const uint8_t* input,
                       const size_t inputSize,
                       size_t* outputSize);

#endif // AES_MODES_H
