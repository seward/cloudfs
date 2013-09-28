/*
 * cloudfs: file header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include "object.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define FILE_DEFAULT_MAX	(64 * 1024 * 1024)

#define FILE_LIMIT_RESERVE	32

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache table

extern const struct object_cache_intr file_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     List struct of cache data

struct file_cache {
	struct object_cache obj;
	int32_t fd;
	uint32_t len;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Initialization

void file_load();

////////////////////////////////////////////////////////////////////////////////
// Section:     Memory maximums and capacity

uint64_t file_get_max();
uint64_t file_get_capacity();

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache operations

struct object_cache *file_create();
int file_read(struct object_cache *cache, uint32_t offt, char *buf, uint32_t *len);
int file_write(struct object_cache *cache, uint32_t offt, const char *buf, uint32_t len);
int file_destroy(struct object_cache *cache);
