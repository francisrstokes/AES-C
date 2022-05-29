#ifndef AES_TEST_H
#define AES_TEST_H

#include <assert.h>
#include "aes.h"
#include "modes.h"
#include "util.h"

// Unit tests
void test_gf_multiply(void);
void test_sub_bytes(void);
void test_key_schedule(void);
void test_shift_rows(void);
void test_inv_shift_rows(void);
void test_mix_columns(void);
void test_encrypt(void);
void test_decrypt(void);

// Integration tests
void test_ecb(void);
void test_cbc(void);

void run_tests(void);

#endif // AES_TEST_H