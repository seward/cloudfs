/*
 * cloudfs: crypt header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define CRYPT_KEY_SIZE        32
#define CRYPT_IV_SIZE         16
#define CRYPT_KEYCHECK_MAGIC  0x1a
#define CRYPT_MAX_PASSWORD    256

////////////////////////////////////////////////////////////////////////////////
// Section:     Crypt initialization

void crypt_load();
void crypt_unload();

////////////////////////////////////////////////////////////////////////////////
// Section:     Get password

void crypt_getpass();

////////////////////////////////////////////////////////////////////////////////
// Section:     Keycheck

void crypt_keycheck_set(char *keycheck, uint32_t size);
bool crypt_keycheck_test(char *keycheck, uint32_t size);

////////////////////////////////////////////////////////////////////////////////
// Section:     Encryption / Decryption

bool crypt_has_cipher();
bool crypt_enc(const char *in_buf, uint32_t in_len, char **out_buf,
               uint32_t *out_len);
bool crypt_dec(const char *in_buf, uint32_t in_len, char **out_buf,
               uint32_t *out_len, bool suppress_error);
