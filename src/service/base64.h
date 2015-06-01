/*
 * cloudfs: base64 header
 *   By Benjamin Kittridge. Copyright (C) 2015, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Base64 Encode

void base64_encode(const char *in_str, uint32_t in_len, char **out_str);

