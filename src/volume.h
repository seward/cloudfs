/*
 * cloudfs: volume header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>
#include "store.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define VOLUME_VERSION			1

#define VOLUME_MAX			256
#define VOLUME_CAP_STRING_MAX		32
#define VOLUME_NAME_MAX			64

#define VOLUME_LOCK_PREFIX		"cloudfs.lock."
#define VOLUME_LOCK_STRING_MAX		(sizeof(VOLUME_LOCK_PREFIX) + VOLUME_NAME_MAX + 1)
#define VOLUME_LOCK_DATA		"**LOCK**"

#define VOLUME_METADATA_PREFIX		"cloudfs.metadata."
#define VOLUME_METADATA_STRING_MAX	(sizeof(VOLUME_METADATA_PREFIX) + VOLUME_NAME_MAX + 1)

#define VOLUME_KEYCHECK_SIZE		64
#define VOLUME_FORMAT_SIZE		32

#define VOLUME_OBJECT_PREFIX		"cloudfs.object."
#define VOLUME_OBJECT_STRING_MAX	(sizeof(VOLUME_OBJECT_PREFIX) + VOLUME_NAME_MAX + 35)

#define VOLUME_LIST_FORMAT		"%-15s %-8s %-10s %-21s %-6s %-8s"

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume object identifier

struct volume_object {
	uint64_t index, chunk;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume metadata structure

enum volume_metadata_flags {
	VOLUME_ENCRYPT  = 1 << 0,
};

struct volume_metadata {
	uint32_t version, flags;
	uint64_t capacity, ctime;
	char keycheck[VOLUME_KEYCHECK_SIZE];
	char format[VOLUME_FORMAT_SIZE];
} __attribute__((packed));

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume interface table definition

enum volume_intr_flags {
	VOLUME_NEED_SIZE = 1 << 0,
};

struct volume_intr {
	void (*mount)   (const struct volume_metadata *, const char *);
	void (*unmount) (const struct volume_metadata *, const char *);
	void (*fsck)    (const struct volume_metadata *);

	uint32_t flags;
};

struct volume_intr_opt {
	const char *name;
	const struct volume_intr *intr;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume operation table definition

struct volume_oper {
	const char *name;
	void (*func)();
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume initialization

void volume_load();
void volume_unload();

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume operation functions

void volume_create();
void volume_mount();
void volume_unmount();
void volume_fsck();
void volume_list();
void volume_delete();

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume mutex

void volume_mutex_check();
void volume_mutex_create();
void volume_mutex_destroy();

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume format

void volume_intr_load(struct volume_metadata **md_out);
bool volume_intr_set_format(const char *fmt);

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume interface functions

int volume_list_object(struct volume_object prefix, uint32_t max_count, struct store_list *list);
int volume_put_object(struct volume_object object, const char *buf, uint32_t len);
int volume_get_object(struct volume_object object, char **buf, uint32_t *len);
int volume_exists_object(struct volume_object object);
int volume_delete_object(struct volume_object object);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object name formatting

void volume_metadata_string(char name[static VOLUME_METADATA_STRING_MAX]);
void volume_lock_string(char name[static VOLUME_LOCK_STRING_MAX]);
void volume_object_string(char name[static VOLUME_OBJECT_STRING_MAX],
		struct volume_object object);

////////////////////////////////////////////////////////////////////////////////
// Section:     File size conversion

bool volume_str_to_size(const char *str, uint64_t *size);
void volume_size_to_str(uint64_t size, char *str, uint32_t len);

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume selection

const char *volume_get_selected();
