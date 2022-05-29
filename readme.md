# AES Implementation In C

**⚠️ DO NOT USE THIS CODE IN PRODUCTION**

This is a very literal, non-performant, non-robust implementation of AES in pure C. It is likely to be vulnerable to side-channel timing attacks, and really shouldn't be used for anything aside from learning about how the AES algorithm works. I've tried to keep the code readable, and added comments to aid my own understanding.

## Features

- 128-bit encryption and decryption
- Electronic Code Book (ECB) mode of operation
- Cipher Block Chaining (CBC) mode of operation
