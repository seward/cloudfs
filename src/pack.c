/*
 * cloudfs: pack source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <zlib.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "pack.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       pack
// Description: Compression / Decompression for volume

////////////////////////////////////////////////////////////////////////////////
// Section:     Compression / Uncompression

bool pack_compress(const char *in_buf, uint32_t in_len, char **out_buf, uint32_t *out_len) {
	struct pack_header *hdr;
	char *sbuf, *rbuf;
	uLongf rlen;
	
	if (!(sbuf = malloc(sizeof(*hdr) + in_len)))
		stderror("malloc");
	
	hdr = (struct pack_header*) sbuf;
	hdr->flag = 0;
	hdr->orig_len = in_len;
	
	rbuf = sbuf + sizeof(*hdr);
	rlen = in_len;
	if (compress((Bytef*) rbuf, &rlen, (const Bytef*) in_buf, in_len) == Z_OK)
		hdr->flag |= PACK_FLAG_COMPRESSED;
	else
		memcpy(rbuf, in_buf, rlen);
	
	*out_buf = sbuf;
	*out_len = sizeof(*hdr) + rlen;
	return true;
}

bool pack_uncompress(const char *in_buf, uint32_t in_len, char **out_buf, uint32_t *out_len) {
	struct pack_header *hdr;
	char *rbuf;
	uLongf rlen;

	if (in_len < sizeof(*hdr)) {
		warning("Buffer for decompression has invalid size");
		return false;
	}
	hdr = (struct pack_header*) in_buf;
	in_buf += sizeof(*hdr);
	in_len -= sizeof(*hdr);

	if (!(hdr->flag & PACK_FLAG_COMPRESSED)) {
		rlen = in_len;
		if (!(rbuf = malloc(rlen)))
			stderror("malloc");
		memcpy(rbuf, in_buf, rlen);
		
		*out_buf = rbuf;
		*out_len = rlen;
		return true;
	}
	
	rlen = hdr->orig_len;
	if (!(rbuf = malloc(rlen))) {
		warning("Decompression alocation failed, likely invalid length");
		return false;
	}

	if (uncompress((Bytef*) rbuf, &rlen, (const Bytef*) in_buf, in_len) != Z_OK) {
		free(rbuf);
		warning("Decompression failed");
		return false;
	}
	
	*out_buf = rbuf;
	*out_len = rlen;
	return true;
}
