#include <malloc.h>

#include "modes.h"
#include "aes.h"

static size_t inline FillBlock(
  AES_Block_t block,
  uint8_t* data,
  size_t bytesLeftInput
) {
  if (bytesLeftInput >= 16) {
    memcpy(block, data, 16);
    return 16;
  }

  memcpy(block, data, bytesLeftInput);
  size_t bytesToPad = 16 - bytesLeftInput;
  for (size_t i = bytesLeftInput; i < 16; i++) {
    ((uint8_t*)(block))[i] = bytesToPad;
  }
  return bytesLeftInput;
}

uint8_t* AES_EncryptFileECB(
  const uint8_t* key,
  const uint8_t* input,
  const size_t inputSize,
  size_t* outputSize
) {
  // When the input is too small to fill a complete last block, we need to add padding
  size_t bytesToPad = inputSize % 16;

  // If the input is exactly a the right size for a block, we still add one blocks worth
  // of padding
  if (bytesToPad == 0) {
    bytesToPad = 16;
  }

  // Create an input pointer we can mutate
  uint8_t* inputPtr = input;

  // Write the outsize size, and allocate the output buffer
  *outputSize = inputSize + bytesToPad;
  const uint8_t* outputBuffer = malloc(*outputSize);
  uint8_t* outputWritePtr = outputBuffer;

  // Create the key schedule
  AES_Block_t keySchedule[NUM_ROUND_KEYS_128] = {};
  AES_KeySchedule128(key, keySchedule);

  // Create a state block, and keep track of the number of bytes left in the input
  AES_Block_t state;
  size_t bytesLeftInInput = inputSize;

  while (bytesLeftInInput > 0) {
    // Load input data into state and increment the input pointer
    bytesLeftInInput -= FillBlock(state, inputPtr, bytesLeftInInput);
    inputPtr += 16;

    // Encrypt the block
    AES_EncryptBlock(state, keySchedule);

    // Write to the output buffer and increment the write pointer
    memcpy(outputWritePtr, state, 16);
    outputWritePtr += 16;
  }

  if (bytesToPad == 16) {
    for (size_t i = 0; i < 16; i++) {
      *outputWritePtr++ = 16;
    }
  }

  // Done, return the buffer
  return outputBuffer;
}
