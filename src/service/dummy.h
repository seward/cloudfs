/*
 * cloudfs: dummy header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include "store.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Service table

extern const struct store_intr dummy_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define DUMMY_MAX_PATH  (1 << 10)
#define DUMMY_DIR_PERM  00755

////////////////////////////////////////////////////////////////////////////////
// Section:     Load

void dummy_load();

////////////////////////////////////////////////////////////////////////////////
// Section:     Buckets

int dummy_create_bucket(const char *bucket);
int dummy_exists_bucket(const char *bucket);
int dummy_delete_bucket(const char *bucket);

////////////////////////////////////////////////////////////////////////////////
// Section:     Objects

int dummy_list_object(const char *bucket, const char *prefix,
                      uint32_t max_count, struct store_list *list);
int dummy_put_object(const char *bucket, const char *object,
                     const char *buf, uint32_t len);
int dummy_get_object(const char *bucket, const char *object,
                     char **buf, uint32_t *len);
int dummy_exists_object(const char *bucket, const char *object);
int dummy_delete_object(const char *bucket, const char *object);
