/*
 * cloudfs: trxlog header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define TRXLOG_STEP		32

////////////////////////////////////////////////////////////////////////////////
// Section:     Structs

struct trxlog_range {
	uint32_t from, to;
};

struct trxlog {
	struct trxlog_range *range;
	uint32_t size, alloc_size;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Functions

void trxlog_add(struct trxlog *t, uint32_t from, uint32_t len);
bool trxlog_match(struct trxlog *t, uint32_t from, uint32_t len);
void trxlog_list(struct trxlog *t, uint32_t from, uint32_t to, uint32_t *len, bool *mark);
void trxlog_copy(struct trxlog *t, struct trxlog *t2);
void trxlog_free(struct trxlog *t);
