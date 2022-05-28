#ifndef AES_MODES_H
#define AES_MODES_H

#include "common.h"

uint8_t* AES_EncryptFileECB(const uint8_t* key,
                       const uint8_t* input,
                       const size_t inputSize,
                       size_t* outputSize);

uint8_t* AES_DecryptFileECB(const uint8_t* key,
                       const uint8_t* input,
                       const size_t inputSize,
                       size_t* outputSize);

#endif // AES_MODES_H
