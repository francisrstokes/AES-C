#ifndef AES_ARGS_H
#define AES_ARGS_H

#include "common.h"
#include <argp.h>

struct arguments {
  enum { RUN_TESTS, NO_ARGS, ENCRYPT, DECRYPT } mode;

  bool haveKeyFile;
  bool haveInFile;
  bool haveOutFile;

  char* keyFile;
  char* inFile;
  char* outFile;
};

#endif // AES_ARGS_H
