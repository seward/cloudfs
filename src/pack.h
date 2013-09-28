/*
 * cloudfs: pack header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Pack header

enum {
	PACK_FLAG_COMPRESSED	= 1 << 0,
};

struct pack_header {
	uint8_t flag;
	uint32_t orig_len;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Compression / Uncompression

bool pack_compress(const char *in_buf, uint32_t in_len, char **out_buf, uint32_t *out_len);
bool pack_uncompress(const char *in_buf, uint32_t in_len, char **out_buf, uint32_t *out_len);
