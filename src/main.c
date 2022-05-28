#include <stdio.h>
#include <malloc.h>

#include "args.h"
#include "test.h"
#include "modes.h"

extern struct argp argp;

int main(int argc, char *argv[]) {
  struct arguments arguments = {0};
  arguments.mode = NO_ARGS;
  error_t parseResult = argp_parse(&argp, argc, argv, 0, 0, &arguments);

  if (parseResult == ARGP_ERR_UNKNOWN) {
    printf("Unknown arguments provided. Use --help for usage\n");
    return 1;
  }

  if (arguments.mode == NO_ARGS) {
    printf("No arguments provided. Use --help for usage\n");
    return 1;
  }

  if (arguments.mode == RUN_TESTS) {
    run_tests();
    return 0;
  }

  if (arguments.mode == ENCRYPT) {
    if (!(arguments.haveInFile && arguments.haveOutFile && arguments.haveKeyFile)) {
      printf("Missing arguments for --encrypt. Use --help for usage\n");
      return 1;
    }

    FILE* fKey = fopen(arguments.keyFile, "rb");
    size_t keyFileSize = 0;
    if (fKey == NULL) {
      printf("Error: Couldn't open key file\n");
      return 1;
    }
    fseek(fKey, 0, SEEK_END);
    keyFileSize = ftell(fKey);
    rewind(fKey);

    if (keyFileSize != 16) {
      printf("Error: Key file must be exactly 128 bits (got %d)\n", keyFileSize / 8);
      return 1;
    }

    FILE* fInput = fopen(arguments.inFile, "rb");
    size_t inFileSize = 0;
    if (fInput == NULL) {
      printf("Error: Couldn't open input file\n");
      return 1;
    }
    fseek(fInput, 0, SEEK_END);
    inFileSize = ftell(fInput);
    rewind(fInput);

    if (inFileSize == 0) {
      printf("Error: Input file is empty\n");
      return 1;
    }

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

    // Encrypt file
    size_t outputSize;
    uint8_t* outputBuffer = AES_EncryptFileECB(keyBuffer, inputBuffer, inFileSize, &outputSize);

    // Write encrypted file
    fwrite(outputBuffer, 1, outputSize, fOutput);

    // free() resources
    free(outputBuffer);
    free(inputBuffer);
    fclose(fOutput);

    return 0;
  }

  if (arguments.mode == DECRYPT) {
    if (!(arguments.haveInFile && arguments.haveOutFile && arguments.haveKeyFile)) {
      printf("Missing arguments for --decrypt. Use --help for usage\n");
      return 1;
    }
    // Do decryption
    return 0;
  }

  return 0;
}
