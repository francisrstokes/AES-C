#include <malloc.h>
#include <stdlib.h>

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
  uint8_t* inputPtr = (uint8_t*)input;

  // Write the outsize size, and allocate the output buffer
  *outputSize = inputSize + bytesToPad;
  const uint8_t* outputBuffer = malloc(*outputSize);
  uint8_t* outputWritePtr = (uint8_t*)outputBuffer;

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

    // Check if we need to add one more block of padding
    if (bytesLeftInInput == 0 && bytesToPad == 16) {
      FillBlock(state, NULL, 0);
      AES_EncryptBlock(state, keySchedule);
      memcpy(outputWritePtr, state, 16);
    }
  }

  // Done, return the buffer
  return (uint8_t*)outputBuffer;
}

uint8_t* AES_DecryptFileECB(
  const uint8_t* key,
  const uint8_t* input,
  const size_t inputSize,
  size_t* outputSize
) {
  // Create an input pointer we can mutate
  uint8_t* inputPtr = (uint8_t*)input;

  // The output will be smaller than the input, but we don't know by how much yet
  // Allocate more space than is needed (maximum 16 bytes)
  const uint8_t* outputBuffer = malloc(inputSize);
  uint8_t* outputWritePtr = (uint8_t*)outputBuffer;

  // Create the key schedule
  AES_Block_t keySchedule[NUM_ROUND_KEYS_128] = {};
  AES_KeySchedule128(key, keySchedule);

  // Create a state block, and keep track of the number of bytes left in the input
  AES_Block_t state;
  size_t bytesLeftInInput = inputSize;

  // Keep track of the last byte in the last block, which tells us how much padding
  // was added, and therefore how large the actual output size is
  uint8_t lastByte;

  while (bytesLeftInInput > 0) {
    // Load input data into state and increment the input pointer
    bytesLeftInInput -= FillBlock(state, inputPtr, bytesLeftInInput);
    inputPtr += 16;

    // Encrypt the block
    AES_DecryptBlock(state, keySchedule);

    if (bytesLeftInInput == 0) {
      // Check for the padding signature
      uint8_t* linearBlock = (uint8_t*)state;
      lastByte = linearBlock[15];

      for (size_t i = 14; i > 15 - lastByte; i--) {
        // There should always be X bytes of X value at the end of the last block
        // If not, we can consider the decryption to be invalid
        if (linearBlock[i] != lastByte) {
          *outputSize = 0;
          return NULL;
        }
      }
    }

    // Write to the output buffer and increment the write pointer
    memcpy(outputWritePtr, state, 16);
    outputWritePtr += 16;
  }

  // We can now correctly report the output size
  *outputSize = inputSize - lastByte;

  // Done, return the buffer
  return (uint8_t*)outputBuffer;
}

uint8_t* AES_EncryptFileCBC(
  const uint8_t* key,
  const uint8_t* input,
  const size_t inputSize,
  size_t* outputSize
) {
  // Get a random 128 bit initial value
  // Note that this is not a secure way of doing this. This initial value
  // is transmitted in the clear, but it would still actually be best to
  // generate this cryptographically
  uint8_t iv[16];
  for (size_t i = 0; i < 16; i++) {
    iv[i] = rand() & 0xff;
  }

  // When the input is too small to fill a complete last block, we need to add padding
  size_t bytesToPad = inputSize % 16;

  // If the input is exactly a the right size for a block, we still add one blocks worth
  // of padding
  if (bytesToPad == 0) {
    bytesToPad = 16;
  }

  // Create an input pointer we can mutate
  uint8_t* inputPtr = (uint8_t*)input;

  // Write the outsize size, and allocate the output buffer
  // We add an additional 16 bytes for the initial value (iv)
  *outputSize = inputSize + bytesToPad + 16;
  const uint8_t* outputBuffer = malloc(*outputSize);
  uint8_t* outputWritePtr = (uint8_t*)outputBuffer;

  // Write the iv to the output buffer
  memcpy(outputWritePtr, iv, 16);
  outputWritePtr += 16;

  // Setup a previousState that we can use to xor the plaintext with
  uint8_t prevState[16];
  memcpy(prevState, iv, 16);

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

    // xor with the prevState
    for (size_t i = 0; i < 16; i++) {
      ((uint8_t*)state)[i] ^= prevState[i];
    }

    // Encrypt the block
    AES_EncryptBlock(state, keySchedule);

    // Write to the output buffer and increment the write pointer
    memcpy(outputWritePtr, state, 16);
    outputWritePtr += 16;

    // Write the encrypted block to the previous state
    memcpy(prevState, state, 16);

    // Check if we need to add one more block of padding
    if (bytesLeftInInput == 0 && bytesToPad == 16) {
      // In this case, we can skip FillBlock and calculate the result directly
      for (size_t i = 0; i < 16; i++) {
        ((uint8_t*)state)[i] = 16 ^ prevState[i];
      }
      AES_EncryptBlock(state, keySchedule);
      memcpy(outputWritePtr, state, 16);
    }
  }

  // Done, return the buffer
  return (uint8_t*)outputBuffer;
}

uint8_t* AES_DecryptFileCBC(
  const uint8_t* key,
  const uint8_t* input,
  const size_t inputSize,
  size_t* outputSize
) {
  // Create an input pointer we can mutate
  uint8_t* inputPtr = (uint8_t*)input;

  // Check that the input is large enough to contain the iv + at least one block
  if (inputSize < 32) {
    *outputSize = 0;
    return NULL;
  }

  // Point at the first previous encrypted block, which in the initial case is actually
  // the initial value (iv) - not actually a real encrypted block
  uint8_t* prevState = inputPtr;

  // Move the input pointer forward to the first actually encrypted block
  inputPtr += 16;

  // The output will be smaller than the input, but we don't know by how much yet
  // Allocate more space than is needed (maximum 32 bytes)
  const uint8_t* outputBuffer = malloc(inputSize);
  uint8_t* outputWritePtr = (uint8_t*)outputBuffer;

  // Create the key schedule
  AES_Block_t keySchedule[NUM_ROUND_KEYS_128] = {};
  AES_KeySchedule128(key, keySchedule);

  // Create a state block, and keep track of the number of bytes left in the input
  AES_Block_t state;
  size_t bytesLeftInInput = inputSize - 16;

  // Keep track of the last byte in the last block, which tells us how much padding
  // was added, and therefore how large the actual output size is
  uint8_t lastByte;

  while (bytesLeftInInput > 0) {
    // Load input data into state and increment the input pointer
    bytesLeftInInput -= FillBlock(state, inputPtr, bytesLeftInInput);
    inputPtr += 16;

    // Encrypt the block
    AES_DecryptBlock(state, keySchedule);

    // xor with the previous encrypted block
    for (size_t i = 0; i < 16; i++) {
      ((uint8_t*)state)[i] ^= prevState[i];
    }

    // Move the previous state forward
    prevState += 16;

    if (bytesLeftInInput == 0) {
      // Check for the padding signature
      uint8_t* linearBlock = (uint8_t*)state;
      lastByte = linearBlock[15];

      for (size_t i = 14; i > 15 - lastByte; i--) {
        // There should always be X bytes of X value at the end of the last block
        // If not, we can consider the decryption to be invalid
        if (linearBlock[i] != lastByte) {
          *outputSize = 0;
          return NULL;
        }
      }
    }

    // Write to the output buffer and increment the write pointer
    memcpy(outputWritePtr, state, 16);
    outputWritePtr += 16;
  }

  // We can now correctly report the output size, which is the input size,
  // less the 16 bytes required for the iv, less any padding added
  *outputSize = inputSize - 16 - lastByte;

  // Done, return the buffer
  return (uint8_t*)outputBuffer;
}
