#include "args.h"
#include "string.h"

const char *argp_program_version = "aes-c 0.0.1";
const char *argp_program_bug_address = "https://github.com/francisrstokes/aes-c/issues";
static char doc[] = "Simple AES implementation";
static char args_doc[] = "...";

static struct argp_option options[] = {
  { "test",     't', 0,           0, "Run the test suite."},
  { "key-file", 'k', "KEY_FILE",  0, "File containing 128-bit key."},
  { "in-file",  'i', "IN_FILE",   0, "Input file."},
  { "out-file", 'o', "OUT_FILE",  0, "Output file."},
  { "encrypt",  'e',  0,          0, "Encrypt."},
  { "decrypt",  'd',  0,          0, "Decrypt."},
  { "mode",     'm', "MODE",      0, "Mode (ecb / cbc)."},
  { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
      case 't': {
        arguments->operation = RUN_TESTS;
        break;
      }

      case 'e': {
        arguments->operation = ENCRYPT;
        break;
      }

      case 'd': {
          arguments->operation = DECRYPT;
        break;
      }

      case 'm': {
        if (strncmp(arg, "ecb", 3) == 0) {
          arguments->mode = ECB;
        } else if (strncmp(arg, "cbc", 3) == 0) {
          arguments->mode = CBC;
        } else {
          return ARGP_ERR_UNKNOWN;
        }
        break;
      }

      case 'k': {
        arguments->haveKeyFile = true;
        arguments->keyFile = arg;
        break;
      }

      case 'i': {
        arguments->haveInFile = true;
        arguments->inFile = arg;
        break;
      }

      case 'o': {
        arguments->haveOutFile = true;
        arguments->outFile = arg;
        break;
      }

      case ARGP_KEY_ARG: return 0;
      default: return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };
