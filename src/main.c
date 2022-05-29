#include <stdio.h>
#include <malloc.h>

#include "args.h"
#include "test.h"
#include "modes.h"

extern struct argp argp;

size_t GetFileSize(FILE* fp);

// Define a table of encryption/decryption function, indexed by mode
static CryptoOpFn EncryptFn[] = {
  AES_EncryptFileECB,
  AES_EncryptFileCBC,
};

static CryptoOpFn DecryptFn[] = {
  AES_DecryptFileECB,
  AES_DecryptFileCBC,
};

int main(int argc, char *argv[]) {
  struct arguments arguments = {0};
  arguments.operation = NO_ARGS;
  arguments.mode = ECB;
  error_t parseResult = argp_parse(&argp, argc, argv, 0, 0, &arguments);

  //////////////////////////////////////////////////////////////////////////////
  //                           Error conditions
  //////////////////////////////////////////////////////////////////////////////
  if (parseResult == ARGP_ERR_UNKNOWN) {
    printf("Unknown arguments provided. Use --help for usage\n");
    return 1;
  }

  if (arguments.operation == NO_ARGS) {
    printf("No arguments provided. Use --help for usage\n");
    return 1;
  }

  //////////////////////////////////////////////////////////////////////////////
  //                                 Tests
  //////////////////////////////////////////////////////////////////////////////
  if (arguments.operation == RUN_TESTS) {
    run_tests();
    return 0;
  }

  //////////////////////////////////////////////////////////////////////////////
  //                             Operations
  //////////////////////////////////////////////////////////////////////////////

  // All further operations will require these options
  if (!(arguments.haveInFile && arguments.haveOutFile && arguments.haveKeyFile)) {
    printf("Missing arguments for operation. Use --help for usage\n");
    return 1;
  }

  // Open the key file
  FILE* fKey = fopen(arguments.keyFile, "rb");
  size_t keyFileSize = 0;
  if (fKey == NULL) {
    printf("Error: Couldn't open key file\n");
    return 1;
  }

  keyFileSize = GetFileSize(fKey);
  if (keyFileSize != 16) {
    printf("Error: Key file must be exactly 128 bits (got %d)\n", keyFileSize / 8);
    return 1;
  }

  // Open the input file
  FILE* fInput = fopen(arguments.inFile, "rb");
  size_t inFileSize = 0;
  if (fInput == NULL) {
    printf("Error: Couldn't open input file\n");
    return 1;
  }

  inFileSize = GetFileSize(fInput);
  if (inFileSize == 0) {
    printf("Error: Input file is empty\n");
    return 1;
  }

  // Open the output file
  FILE* fOutput = fopen(arguments.outFile, "wb");
  if (fOutput == NULL) {
    printf("Error: Couldn't open output file for writing\n");
    return 1;
  }

  // Read the key into a buffer
  uint8_t keyBuffer[16];
  fread(keyBuffer, 1, 16, fKey);
  fclose(fKey);

  // Read the input file into a buffer
  uint8_t* inputBuffer = malloc(inFileSize);
  fread(inputBuffer, 1, inFileSize, fInput);
  fclose(fInput);

  if (arguments.operation == ENCRYPT) {
    // Encrypt file
    size_t outputSize;
    uint8_t* outputBuffer = EncryptFn[arguments.mode](keyBuffer, inputBuffer, inFileSize, &outputSize);

    // Write encrypted file
    fwrite(outputBuffer, 1, outputSize, fOutput);

    // free() resources
    free(outputBuffer);
    free(inputBuffer);
    fclose(fOutput);

    return 0;
  }

  if (arguments.operation == DECRYPT) {
    // Encrypt file
    size_t outputSize;
    uint8_t* outputBuffer = DecryptFn[arguments.mode](keyBuffer, inputBuffer, inFileSize, &outputSize);

    if (outputBuffer == NULL) {
      printf("Unable to properly decrypt file\n");
      return 1;
    }

    // Write decrypted file
    fwrite(outputBuffer, 1, outputSize, fOutput);

    // free() resources
    free(outputBuffer);
    free(inputBuffer);
    fclose(fOutput);

    return 0;
  }

  return 0;
}

size_t GetFileSize(FILE* fp) {
  fseek(fp, 0, SEEK_END);
  size_t fileSize = ftell(fp);
  rewind(fp);
  return fileSize;
}
