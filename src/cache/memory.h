/*
 * cloudfs: memory header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include "object.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define MEMORY_DEFAULT_MAX	(16 * 1024 * 1024)

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache table

extern const struct object_cache_intr memory_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     List struct of cache data

struct memory_cache {
	struct object_cache obj;
	char *data;
	uint32_t len;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Initialization

void memory_load();

////////////////////////////////////////////////////////////////////////////////
// Section:     Memory maximums and capacity

uint64_t memory_get_max();
uint64_t memory_get_capacity();

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache operations

struct object_cache *memory_create();
int memory_read(struct object_cache *cache, uint32_t offt, char *buf, uint32_t *len);
int memory_write(struct object_cache *cache, uint32_t offt, const char *buf, uint32_t len);
int memory_destroy(struct object_cache *cache);
