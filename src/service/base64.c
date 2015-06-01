/*
 * cloudfs: base64 source
 *   By Benjamin Kittridge. Copyright (C) 2015, All rights reserved.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       Base64
// Description: Base64 utilities

////////////////////////////////////////////////////////////////////////////////
// Section:     Base64 encode

void base64_encode(const char *in_str, uint32_t in_len, char **out_str) {
  static const char *base64_lookup =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/";
  const char *ptr;
  char *out;
  uint8_t *in;
  int32_t len;
  uint32_t c;

  len = (((in_len / 3) + 1) * 4) + 1;
  if (!(out = malloc(len)))
    stderror("malloc");

  for (c = 0, ptr = in_str; ptr < in_str + in_len; ptr += 3) {
    in = (uint8_t*)ptr;
    len = (in_str + in_len) - ptr;

    out[c++] = base64_lookup[in[0] >> 2];
    out[c++] = base64_lookup[((in[0] & 0x03) << 4) |
                             (len > 1 ? ((in[1] & 0xf0) >> 4) : 0)];
    out[c++] = len > 1 ? base64_lookup[((in[1] & 0x0f) << 2) |
                               (len > 2 ? ((in[2] & 0xc0) >> 6) : 0)] : '=';
    out[c++] = len > 2 ? base64_lookup[in[2] & 0x3f] : '=';
  }
  out[c] = 0;

  *out_str = out;
}

