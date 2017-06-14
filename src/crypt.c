/*
 * cloudfs: crypt source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <termios.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "crypt.h"
#include "volume.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       crypt
// Description: Encryption for volume

////////////////////////////////////////////////////////////////////////////////
// Section:     Cipher information

static const EVP_CIPHER *crypt_cipher = NULL;

static bool crypt_cipher_enabled = false;

static uint8_t crypt_cipher_key[CRYPT_KEY_SIZE];

static int32_t crypt_blocksize = 0;

////////////////////////////////////////////////////////////////////////////////
// Section:     Crypt construction / destruction

void crypt_load() {
  const char *password;

  if (config_get("password-prompt"))
    crypt_getpass();

  password = config_get("password");
  if (!password || !*password)
    return;

  crypt_cipher = EVP_aes_256_cbc();
  if (EVP_CIPHER_iv_length(crypt_cipher) != CRYPT_IV_SIZE)
    error("Cipher IV length does not match built-in length");
  if (EVP_CIPHER_key_length(crypt_cipher) != CRYPT_KEY_SIZE)
    error("Cipher KEY length does not match built-in length");

  EVP_BytesToKey(crypt_cipher, EVP_sha1(), NULL, (uint8_t*) password,
                 strlen(password), 8, crypt_cipher_key, NULL);

  crypt_blocksize = EVP_CIPHER_block_size(crypt_cipher);
  crypt_cipher_enabled = true;
}

void crypt_unload() {
  crypt_cipher_enabled = false;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Get password

void crypt_getpass() {
  struct termios old_flags, flags;
  char password[CRYPT_MAX_PASSWORD];
  uint32_t len;

  if (tcgetattr(0, &old_flags) != 0)
    stderror("tcgetattr");

  flags = old_flags;
  flags.c_lflag &= ~ECHO;
  flags.c_lflag |= ECHONL;

  if (tcsetattr(fileno(stdin), TCSANOW, &flags) != 0)
    stderror("tcsetattr");

  printf("Password: ");
  if (!fgets(password, sizeof(password), stdin))
    error("No password specified, quitting");

  len = strlen(password);
  while (len && isspace(password[len - 1]))
    password[--len] = 0;

  if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0)
    stderror("tcsetattr");

  config_set("password", password);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Keycheck

void crypt_keycheck_set(char *keycheck, uint32_t size) {
  char *buf;
  uint32_t len, keysize;

  assert(size > (crypt_blocksize + CRYPT_IV_SIZE));
  keysize = size - (crypt_blocksize + CRYPT_IV_SIZE);
  memset(keycheck, CRYPT_KEYCHECK_MAGIC, keysize);

  if (!crypt_enc(keycheck, keysize, &buf, &len) || len > size)
    error("Encryption for keycheck failed");
  memcpy(keycheck, buf, len);
  free(buf);
}

bool crypt_keycheck_test(char *keycheck, uint32_t size) {
  char *buf;
  uint32_t len, i;

  if (!crypt_dec(keycheck, size, &buf, &len, true) || !len)
    return false;
  for (i = 0; i < len; i++) {
    if (buf[i] != CRYPT_KEYCHECK_MAGIC) {
      free(buf);
      return false;
    }
  }
  free(buf);
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Encryption / Decryption

bool crypt_has_cipher() {
  return crypt_cipher_enabled;
}

bool crypt_enc(const char *in_buf, uint32_t in_len, char **out_buf,
               uint32_t *out_len) {
  EVP_CIPHER_CTX *ctx;
  uint8_t iv[CRYPT_IV_SIZE];
  char *out_rbuf;
  int32_t out_rlen, out_flen;

  if (!crypt_cipher_enabled) {
    warning("Encryption used without initialization");
    return false;
  }

  if (RAND_bytes(iv, sizeof(iv)) <= 0) {
    warning("RAND_bytes failed");
    return false;
  }

  ctx = EVP_CIPHER_CTX_new();

  if (!EVP_EncryptInit_ex(ctx, crypt_cipher, NULL, crypt_cipher_key, iv)) {
    warning("EVP_EncryptInit_ex failed");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (!(out_rbuf = malloc(sizeof(iv) + in_len + crypt_blocksize)))
    stderror("malloc");
  memcpy(out_rbuf, iv, sizeof(iv));
  out_rlen = sizeof(iv);

  if (!EVP_EncryptUpdate(ctx, (uint8_t *)out_rbuf + out_rlen, &out_flen,
                         (uint8_t *)in_buf, in_len)) {
    warning("EVP_EncryptUpdate failed");
    free(out_rbuf);
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  out_rlen += out_flen;

  if (!EVP_EncryptFinal_ex(ctx, (uint8_t*) out_rbuf + out_rlen, &out_flen)) {
    warning("EVP_EncryptFinal_ex failed");
    free(out_rbuf);
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  out_rlen += out_flen;

  assert(out_rlen >= 0);
  *out_buf = out_rbuf;
  *out_len = out_rlen;

  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool crypt_dec(const char *in_buf, uint32_t in_len, char **out_buf,
               uint32_t *out_len, bool suppress_error) {
  EVP_CIPHER_CTX *ctx;
  uint8_t iv[CRYPT_IV_SIZE];
  char *out_rbuf;
  int32_t out_rlen, out_flen;

  if (!crypt_cipher_enabled) {
    warning("Encryption used without initialization");
    return false;
  }

  if (in_len < sizeof(iv)) {
    warning("Buffer for decryption has invalid size");
    return false;
  }
  memcpy(iv, in_buf, sizeof(iv));
  in_buf += sizeof(iv);
  in_len -= sizeof(iv);

  ctx = EVP_CIPHER_CTX_new();

  if (!EVP_DecryptInit_ex(ctx, crypt_cipher, NULL, crypt_cipher_key, iv)) {
    if (!suppress_error)
      warning("EVP_DecryptInit_ex failed");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (!(out_rbuf = malloc(in_len + crypt_blocksize)))
    stderror("malloc");
  out_rlen = 0;

  if (!EVP_DecryptUpdate(ctx, (uint8_t *)out_rbuf + out_rlen, &out_flen,
                         (uint8_t *)in_buf, in_len)) {
    if (!suppress_error)
      warning("EVP_DecryptUpdate failed");
    free(out_rbuf);
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  out_rlen += out_flen;

  if (!EVP_DecryptFinal_ex(ctx, (uint8_t *)out_rbuf + out_rlen, &out_flen)) {
    if (!suppress_error)
      warning("EVP_DecryptFinal_ex failed");
    free(out_rbuf);
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  out_rlen += out_flen;

  assert(out_rlen >= 0);
  *out_buf = out_rbuf;
  *out_len = out_rlen;

  EVP_CIPHER_CTX_free(ctx);
  return true;
}
