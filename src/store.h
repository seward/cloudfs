/*
 * cloudfs: store header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Service interface objects

enum store_ret {
	SUCCESS       =  0,
	SYS_ERROR     = -1,
	USER_ERROR    = -2,
	NOT_FOUND     = -4,
};

struct store_list {
	uint32_t size;
	char **item;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Service table definition

struct store_intr {
	void (*load)         (void);
	void (*unload)       (void);
	
	int (*list_bucket)   (const char *prefix, uint32_t max_count,
				struct store_list *list);
	int (*create_bucket) (const char *bucket);
	int (*exists_bucket) (const char *bucket);
	int (*delete_bucket) (const char *bucket);
	
	int (*list_object)   (const char *bucket, const char *prefix,
				uint32_t max_count, struct store_list *list);
	int (*put_object)    (const char *bucket, const char *object,
				const char *buf, uint32_t len);
	int (*get_object)    (const char *bucket, const char *object,
				char **buf, uint32_t *len);
	int (*exists_object) (const char *bucket, const char *object);
	int (*delete_object) (const char *bucket, const char *object);
};

struct store_intr_opt {
	const char *name;
	const struct store_intr *intr;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Storage initialization

void store_load();
void store_unload();

////////////////////////////////////////////////////////////////////////////////
// Section:     Interface functions

int store_list_bucket(const char *prefix, uint32_t max_count,
			struct store_list *list);
int store_create_bucket(const char *bucket);
int store_exists_bucket(const char *bucket);
int store_delete_bucket(const char *bucket);

int store_list_object(const char *bucket, const char *prefix,
			uint32_t max_count, struct store_list *list);
int store_put_object(const char *bucket, const char *object,
			const char *buf, uint32_t len);
int store_get_object(const char *bucket, const char *object,
			char **buf, uint32_t *len);
int store_exists_object(const char *bucket, const char *object);
int store_delete_object(const char *bucket, const char *object);

////////////////////////////////////////////////////////////////////////////////
// Section:     Store list functions

struct store_list *store_list_new();
void store_list_push(struct store_list *list, const char *item);
void store_list_free(struct store_list *list);

////////////////////////////////////////////////////////////////////////////////
// Section:     Store flags

bool store_get_readonly();
