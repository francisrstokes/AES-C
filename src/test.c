#include "test.h"

void run_tests() {
  test_gf_multiply();
  test_sub_bytes();
  test_shift_rows();
  test_key_schedule();
  test_mix_columns();
  test_encrypt();

  test_inv_shift_rows();
  test_decrypt();
}

void test_gf_multiply() {
  printf("test_gf_multiply\n");
  uint8_t a = 0x57;
  uint8_t b = 0x13;
  uint8_t c = GF_Mult(a, b);

  assert(c == 0xfe);

  b = 1;
  c = GF_Mult(a, b);
  assert(c == a);

  printf("\t[✅] Passed\n");
}

extern uint8_t sbox_encrypt[];
extern uint8_t sbox_decrypt[];
void test_sub_bytes() {
  printf("test_sub_bytes\n");
  AES_Block_t state = {
    { 1,  2,  3,  4  },
    { 5,  6,  7,  8  },
    { 9,  10, 11, 12 },
    { 13, 14, 15, 16 },
  };

  AES_Block_t expectedEncrypt = {
    { 0x7c, 0x77, 0x7b, 0xf2 },
    { 0x6b, 0x6f, 0xc5, 0x30 },
    { 0x01, 0x67, 0x2b, 0xfe },
    { 0xd7, 0xab, 0x76, 0xca },
  };

  AES_Block_t expectedDecrypt = {
    { 1,  2,  3,  4  },
    { 5,  6,  7,  8  },
    { 9,  10, 11, 12 },
    { 13, 14, 15, 16 },
  };

  AES_SubBytes(state, sbox_encrypt);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(state[row][col] == expectedEncrypt[row][col]);
    }
  }

  AES_SubBytes(state, sbox_decrypt);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(state[row][col] == expectedDecrypt[row][col]);
    }
  }
  printf("\t[✅] Passed\n");
}

void test_key_schedule() {
  printf("test_key_schedule\n");

  // The key and expected round keys both come from the Spec, appendix A1 (p27-28)

  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  AES_Block_t roundKeysPtr[NUM_ROUND_KEYS_128] = {};

  AES_KeySchedule128(key, roundKeysPtr);

  AES_Block_t expectedRoundKeys[] = {
    {
      {0x2b, 0x7e, 0x15, 0x16},
      {0x28, 0xae, 0xd2, 0xa6},
      {0xab, 0xf7, 0x15, 0x88},
      {0x09, 0xcf, 0x4f, 0x3c},
    },
    {
      {0xa0, 0xfa, 0xfe, 0x17},
      {0x88, 0x54, 0x2c, 0xb1},
      {0x23, 0xa3, 0x39, 0x39},
      {0x2a, 0x6c, 0x76, 0x05},
    },
    {
      {0xf2, 0xc2, 0x95, 0xf2},
      {0x7a, 0x96, 0xb9, 0x43},
      {0x59, 0x35, 0x80, 0x7a},
      {0x73, 0x59, 0xf6, 0x7f},
    },
    {
      {0x3d, 0x80, 0x47, 0x7d},
      {0x47, 0x16, 0xfe, 0x3e},
      {0x1e, 0x23, 0x7e, 0x44},
      {0x6d, 0x7a, 0x88, 0x3b},
    },
    {
      {0xef, 0x44, 0xa5, 0x41},
      {0xa8, 0x52, 0x5b, 0x7f},
      {0xb6, 0x71, 0x25, 0x3b},
      {0xdb, 0x0b, 0xad, 0x00},
    },
    {
      {0xd4, 0xd1, 0xc6, 0xf8},
      {0x7c, 0x83, 0x9d, 0x87},
      {0xca, 0xf2, 0xb8, 0xbc},
      {0x11, 0xf9, 0x15, 0xbc},
    },
    {
      {0x6d, 0x88, 0xa3, 0x7a},
      {0x11, 0x0b, 0x3e, 0xfd},
      {0xdb, 0xf9, 0x86, 0x41},
      {0xca, 0x00, 0x93, 0xfd},
    },
    {
      {0x4e, 0x54, 0xf7, 0x0e},
      {0x5f, 0x5f, 0xc9, 0xf3},
      {0x84, 0xa6, 0x4f, 0xb2},
      {0x4e, 0xa6, 0xdc, 0x4f},
    },
    {
      {0xea, 0xd2, 0x73, 0x21},
      {0xb5, 0x8d, 0xba, 0xd2},
      {0x31, 0x2b, 0xf5, 0x60},
      {0x7f, 0x8d, 0x29, 0x2f},
    },
    {
      {0xac, 0x77, 0x66, 0xf3},
      {0x19, 0xfa, 0xdc, 0x21},
      {0x28, 0xd1, 0x29, 0x41},
      {0x57, 0x5c, 0x00, 0x6e},
    },
    {
      {0xd0, 0x14, 0xf9, 0xa8},
      {0xc9, 0xee, 0x25, 0x89},
      {0xe1, 0x3f, 0x0c, 0xc8},
      {0xb6, 0x63, 0x0c, 0xa6},
    }
  };

  for (size_t i = 0; i < NUM_ROUND_KEYS_128; i++) {
    for  (size_t row = 0; row < 4; row++) {
      for  (size_t col = 0; col < 4; col++) {
        assert(roundKeysPtr[i][row][col] == expectedRoundKeys[i][row][col]);
      }
    }
  }

  printf("\t[✅] Passed\n");
}

void test_shift_rows() {
  printf("test_shift_rows\n");
  AES_Block_t state = {
    { 1,  2,  3,  4  },
    { 5,  6,  7,  8  },
    { 9,  10, 11, 12 },
    { 13, 14, 15, 16 },
  };

  AES_Block_t expectedShift = {
    { 1,   6, 11, 16 },
    { 5,  10, 15,  4 },
    { 9,  14,  3,  8 },
    { 13,  2,  7, 12 },
  };

  AES_ShiftRows(state);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(state[row][col] == expectedShift[row][col]);
    }
  }

  printf("\t[✅] Passed\n");
}

void test_inv_shift_rows() {
  printf("test_inv_shift_rows\n");

  AES_Block_t input = {
    { 1,  2,  3,  4  },
    { 5,  6,  7,  8  },
    { 9,  10, 11, 12 },
    { 13, 14, 15, 16 },
  };

  AES_Block_t expectedShift = {
    {  1, 14, 11,  8 },
    {  5,  2, 15, 12 },
    {  9,  6,  3, 16 },
    { 13, 10,  7,  4 },
  };

  AES_InvShiftRows(input);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(input[row][col] == expectedShift[row][col]);
    }
  }

  printf("\t[✅] Passed\n");
}

extern uint8_t mix_encrypt_coef[];
extern uint8_t mix_decrypt_coef[];
void test_mix_columns() {
  printf("test_mix_columns\n");

  // Test case from spec, Appendix B (p33)
  AES_Block_t input = {
    {0xd4, 0xbf, 0x5d, 0x30},
    {0xe0, 0xb4, 0x52, 0xae},
    {0xb8, 0x41, 0x11, 0xf1},
    {0x1e, 0x27, 0x98, 0xe5},
  };

  AES_Block_t expectedOutput = {
    {0x04, 0x66, 0x81, 0xe5},
    {0xe0, 0xcb, 0x19, 0x9a},
    {0x48, 0xf8, 0xd3, 0x7a},
    {0x28, 0x06, 0x26, 0x4c},
  };

  AES_MixColumns(input);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(input[row][col] == expectedOutput[row][col]);
    }
  }

  printf("\t[✅] Passed\n");
}

void test_encrypt() {
  printf("test_encrypt\n");

  AES_Block_t input = {
    {0x32, 0x43, 0xf6, 0xa8},
    {0x88, 0x5a, 0x30, 0x8d},
    {0x31, 0x31, 0x98, 0xa2},
    {0xe0, 0x37, 0x07, 0x34},
  };

  AES_Block_t expected = {
    {0x39, 0x25, 0x84, 0x1d},
    {0x02, 0xdc, 0x09, 0xfb},
    {0xdc, 0x11, 0x85, 0x97},
    {0x19, 0x6a, 0x0b, 0x32},
  };

  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  AES_Block_t roundKeysPtr[NUM_ROUND_KEYS_128] = {};
  AES_KeySchedule128(key, roundKeysPtr);

  AES_EncryptBlock(input, roundKeysPtr);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(input[row][col] == expected[row][col]);
    }
  }

  // Also check that the encrypt function doesn't touch the roundKeyPtr
  assert(
       (roundKeysPtr[0][0][0] == key[0])
    && (roundKeysPtr[0][0][1] == key[1])
    && (roundKeysPtr[0][0][2] == key[2])
    && (roundKeysPtr[0][0][3] == key[3])
  );

  printf("\t[✅] Passed\n");
}

void test_decrypt() {
  printf("test_decrypt\n");

  AES_Block_t input = {
    {0x39, 0x25, 0x84, 0x1d},
    {0x02, 0xdc, 0x09, 0xfb},
    {0xdc, 0x11, 0x85, 0x97},
    {0x19, 0x6a, 0x0b, 0x32},
  };

  AES_Block_t expected = {
    {0x32, 0x43, 0xf6, 0xa8},
    {0x88, 0x5a, 0x30, 0x8d},
    {0x31, 0x31, 0x98, 0xa2},
    {0xe0, 0x37, 0x07, 0x34},
  };

  uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  AES_Block_t roundKeysPtr[NUM_ROUND_KEYS_128] = {};
  AES_KeySchedule128(key, roundKeysPtr);

  AES_DecryptBlock(input, roundKeysPtr);

  for  (size_t row = 0; row < 4; row++) {
    for  (size_t col = 0; col < 4; col++) {
      assert(input[row][col] == expected[row][col]);
    }
  }

  // Also check that the encrypt function doesn't touch the roundKeyPtr
  assert(
       (roundKeysPtr[0][0][0] == key[0])
    && (roundKeysPtr[0][0][1] == key[1])
    && (roundKeysPtr[0][0][2] == key[2])
    && (roundKeysPtr[0][0][3] == key[3])
  );

  printf("\t[✅] Passed\n");
}
