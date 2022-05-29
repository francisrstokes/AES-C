# AES Implementation In C

**⚠️ DO NOT USE THIS CODE IN PRODUCTION**

This is a very literal, non-performant, non-robust implementation of AES in pure C. It is likely to be vulnerable to side-channel timing attacks, and really shouldn't be used for anything aside from learning about how the AES algorithm works. I've tried to keep the code readable, and added comments to aid my own understanding.

## Features

- 128-bit encryption and decryption
- Electronic Code Book (ECB) mode of operation
- Cipher Block Chaining (CBC) mode of operation

## Building / Testing

```bash
make      # to build
make test # to run the test suite
```

## Usage

```
Usage: aes-c [OPTION...] ...
Simple AES implementation

  -d, --decrypt              Decrypt.
  -e, --encrypt              Encrypt.
  -i, --in-file=IN_FILE      Input file.
  -k, --key-file=KEY_FILE    File containing 128-bit key.
  -m, --mode=MODE            Mode (ecb / cbc).
  -o, --out-file=OUT_FILE    Output file.
  -t, --test                 Run the test suite.
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to https://github.com/francisrstokes/aes-c/issues.
```