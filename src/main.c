#include "args.h"
#include "test.h"
#include "aes.h"

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
    // Do encryption
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
