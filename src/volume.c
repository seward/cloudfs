/*
 * cloudfs: volume source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "bucket.h"
#include "crypt.h"
#include "pack.h"
#include "object.h"
#include "volume.h"
#include "format/vfs.h"
#include "format/block.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       volume
// Description: Volume management for storage interface

////////////////////////////////////////////////////////////////////////////////
// Section:     Available volume formats

static const struct volume_intr_opt volume_intr_opt_list[] = {
#ifdef HAVE_FUSE
	{   "vfs", &vfs_intr   },
#endif
	{ "block", &block_intr },
};

const struct volume_intr *volume_intr_ptr = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     Selected volume

static const char *volume_selected = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume operations

static const struct volume_oper volume_oper_list[] = {
	{    "create", volume_create   },
	{     "mount", volume_mount    },
	{   "unmount", volume_unmount  },
	{      "fsck", volume_fsck     },
	{      "list", volume_list     },
	{    "delete", volume_delete   },
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume construction / destruction

void volume_load() {
	const struct volume_oper *oper, *oper_end;
	const char *volume;

	if ((volume = config_get("volume"))) {
		if (strchr(volume, '.'))
			error("Volume name cannot contain the character '.'");
		if (strlen(volume) > VOLUME_NAME_MAX)
			error("Volume name too long");
		volume_selected = volume;
	}

	for (oper = volume_oper_list,
	     oper_end = oper + sizearr(volume_oper_list);
	     oper < oper_end;
	     oper++) {
		if (config_get(oper->name)) {
			oper->func();
			exit(0);
		}
	}

	error("Must specify a volume operation, i.e. "
			"--create, --mount, --unmount, --list, --check, or --delete");
}

void volume_unload() {
	volume_selected = NULL;
	volume_intr_ptr = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume operation functions

void volume_create() {
	struct volume_metadata md;
	const char *format, *size;
	char md_name[VOLUME_METADATA_STRING_MAX];
	uint64_t capacity;

	if (!volume_selected)
		error("Must specify a --volume for --create");
	if (strlen(volume_selected) >= VOLUME_NAME_MAX)
		error("Volume name too long");

	if (!(format = config_get("format")))
		format = "vfs";
	if (strlen(format) >= VOLUME_FORMAT_SIZE)
		error("Format name too long");
	if (!volume_intr_set_format(format))
		error("Invalid volume format specified");

	if ((volume_intr_ptr->flags & VOLUME_NEED_SIZE)) {
		if (!(size = config_get("size")))
			error("For target format, --size must be specified");
		if (!volume_str_to_size(size, &capacity))
			error("Invalid size specified, an example would be --size 30G");
	}
	else
		capacity = 0;

	volume_metadata_string(md_name);
	switch (store_exists_object(bucket_get_selected(), md_name)) {
		case NOT_FOUND:
			break;

		case SUCCESS:
			error("Volume \"%s\" already exists", volume_selected);

		default:
			error("Unable to query storage service");
	}

	memset(&md, 0, sizeof(md));
	md.version = VOLUME_VERSION;
	md.flags = 0;
	md.capacity = capacity;
	md.ctime = time(NULL);
	if (crypt_has_cipher()) {
		md.flags |= VOLUME_ENCRYPT;
		crypt_keycheck_set(md.keycheck, sizeof(md.keycheck));
	}
	strcpy(md.format, format);

	if (store_put_object(bucket_get_selected(), md_name,
			(char*) &md, sizeof(md)) != SUCCESS)
		error("Unable to create volume");

	notice("Volume \"%s\" has been created", volume_selected);
}

void volume_mount() {
	struct volume_metadata *md;
	const char *path;

	if (!volume_selected)
		error("Volume must be specified using --volume");
	if (!(path = config_get("mount")))
		error("A path must be specified for --mount");

	volume_intr_load(&md);

	volume_mutex_check();
	if (!store_get_readonly())
		volume_mutex_create();

	if (!volume_intr_ptr->mount)
		error("Volume format does not support this operation");
	volume_intr_ptr->mount(md, path);

	if (!store_get_readonly())
		volume_mutex_destroy();

	free(md);
}

void volume_unmount() {
	struct volume_metadata *md;
	const char *path;

	if (!volume_selected)
		error("Volume must be specified using --volume");
	if (!(path = config_get("unmount")))
		error("A path must be specified for --unmount");

	volume_intr_load(&md);

	if (!volume_intr_ptr->unmount)
		error("Volume format does not support this operation");
	volume_intr_ptr->unmount(md, path);

	free(md);
}

void volume_fsck() {
	struct volume_metadata *md;

	if (!volume_selected)
		error("Volume must be specified using --volume");
	if (store_get_readonly())
		error("Cannot use --fsck and --readonly at the same time");

	volume_intr_load(&md);

	volume_mutex_check();
	volume_mutex_create();

	if (!volume_intr_ptr->fsck)
		error("Volume format does not support this operation");
	volume_intr_ptr->fsck(md);

	volume_mutex_destroy();

	free(md);
}

void volume_list() {
	struct store_list *list;
	uint32_t i, prefix_len;
	bool found;

	list = store_list_new();

	if (store_list_object(bucket_get_selected(),
			VOLUME_METADATA_PREFIX, VOLUME_MAX, list) != SUCCESS)
		error("Unable to list objects");

	notice(VOLUME_LIST_FORMAT,
			"Name", "Format", "Capacity",
			"Creation Time", "Enc.", "Mounted");
	notice(VOLUME_LIST_FORMAT,
			"----", "------", "--------",
			"-------------", "----", "-------");

	prefix_len = strlen(VOLUME_METADATA_PREFIX);
	found = false;

	for (i = 0; i < list->size; i++) {
		struct volume_metadata *md;
		char *md_buf, *volume,
			cap[VOLUME_CAP_STRING_MAX],
			lock[VOLUME_LOCK_STRING_MAX],
			time_str[1 << 9];
		uint32_t md_len;
		struct tm time_tm;
		time_t time_offt;
		bool mounted;

		if (strncmp(list->item[i], VOLUME_METADATA_PREFIX, prefix_len) != 0)
			break;

		volume = list->item[i] + prefix_len;
		if (store_get_object(bucket_get_selected(), list->item[i],
				&md_buf, &md_len) != SUCCESS) {
			warning("Metadata missing for volume %s", volume);
			continue;
		}
		if (md_len < sizeof(struct volume_metadata)) {
			free(md_buf);
			warning("Metadata corrupted for volume %s", volume);
			continue;
		}

		md = (struct volume_metadata*) md_buf;
		if (md->version > VOLUME_VERSION) {
			warning("Volume %s was created for a newer version of cloudfs", volume);
			continue;
		}

		if (!volume_intr_set_format(md->format)) {
			warning("Volume %s has an invalid format", volume);
			continue;
		}

		snprintf(lock, sizeof(lock), VOLUME_LOCK_PREFIX "%s",
			volume);
		mounted = (store_exists_object(bucket_get_selected(), lock) == SUCCESS);

		if ((volume_intr_ptr->flags & VOLUME_NEED_SIZE))
			volume_size_to_str(md->capacity, cap, sizeof(cap));
		else
			strcpy(cap, "N/A");

		time_offt = md->ctime;
		localtime_r(&time_offt, &time_tm);
		strftime(time_str, sizeof(time_str), "%F %T", &time_tm);

		notice(VOLUME_LIST_FORMAT,
				volume, md->format, cap, time_str,
				(md->flags & VOLUME_ENCRYPT) ? "On" : "Off",
				mounted ? "Yes" : "No");
		found = true;

		free(md_buf);
	}

	if (!found)
		notice("No volumes found in bucket");

	store_list_free(list);
}

void volume_delete() {
	struct store_list *list;
	uint32_t i, obj_len;
	char obj_name[VOLUME_OBJECT_STRING_MAX],
		md_name[VOLUME_METADATA_STRING_MAX];
	bool found;

	snprintf(obj_name, sizeof(obj_name), VOLUME_OBJECT_PREFIX "%s.",
			volume_selected);
	obj_len = strlen(obj_name);

	while (1) {
		list = store_list_new();

		if (store_list_object(bucket_get_selected(),
				obj_name, VOLUME_MAX, list) != SUCCESS)
			error("Unable to list objects");

		for (found = false, i = 0; i < list->size; i++) {
			if (strncmp(list->item[i], obj_name, obj_len) != 0)
				break;

			if (store_delete_object(bucket_get_selected(), list->item[i]) != SUCCESS)
				error("Object deleting failed");
			found = true;
		}

		store_list_free(list);

		if (!found)
			break;
	}

	volume_metadata_string(md_name);
	if (store_delete_object(bucket_get_selected(), md_name) != SUCCESS)
		error("Unable to delete volume");

	notice("Volume \"%s\" has been deleted", volume_selected);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume mutex

void volume_mutex_check() {
	char lock_name[VOLUME_METADATA_STRING_MAX];

	volume_lock_string(lock_name);
	switch (store_exists_object(bucket_get_selected(), lock_name)) {
		case NOT_FOUND:
			break;

		case SUCCESS:
			if (config_get("force"))
				break;

			warning("Volume \"%s\" is currently already in use, "
					"or was not cleanly unmounted.",
					volume_selected);
			warning("Mounting the same bucket in multiple instances "
					"will cause problems.");
			error("If you would like to continue anyway, use --force");

		default:
			error("Unable to query storage service");
	}
}

void volume_mutex_create() {
	char lock_name[VOLUME_METADATA_STRING_MAX];

	volume_lock_string(lock_name);
	if (store_put_object(bucket_get_selected(), lock_name,
			VOLUME_LOCK_DATA, strlen(VOLUME_LOCK_DATA)) != SUCCESS)
		error("Unable to create lock for volume");
}

void volume_mutex_destroy() {
	char lock_name[VOLUME_METADATA_STRING_MAX];

	volume_lock_string(lock_name);
	if (store_delete_object(bucket_get_selected(), lock_name) != SUCCESS)
		warning("Unable to delete lock");
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume format

void volume_intr_load(struct volume_metadata **md_out) {
	struct volume_metadata *md;
	char md_name[VOLUME_METADATA_STRING_MAX],
		*md_buf;
	uint32_t md_len;

	if (!volume_selected)
		error("Volume must be specified using --volume");

	volume_metadata_string(md_name);
	if (store_get_object(bucket_get_selected(), md_name, &md_buf, &md_len) != SUCCESS)
		error("Volume \"%s\" not found", volume_selected);

	if (md_len < sizeof(struct volume_metadata))
		error("Metadata corrupted for volume");
	md = (struct volume_metadata*) md_buf;

	if (md->version > VOLUME_VERSION)
		error("Volume was created for a newer version of cloudfs");
	if ((md->flags & VOLUME_ENCRYPT)) {
		if (!crypt_has_cipher())
			error("Volume requires a password");
		if (!crypt_keycheck_test(md->keycheck, sizeof(md->keycheck)))
			error("Volume password is incorrect");
	}

	if (!volume_intr_set_format(md->format))
		error("Invalid volume format specified");

	*md_out = md;
}

bool volume_intr_set_format(const char *fmt) {
	const struct volume_intr_opt *opt, *opt_end;

	for (opt = volume_intr_opt_list,
	     opt_end = opt + sizearr(volume_intr_opt_list);
	     opt < opt_end;
	     opt++) {
		if (!strcasecmp(fmt, opt->name)) {
			volume_intr_ptr = opt->intr;
			return true;
		}
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume interface functions

int volume_list_object(struct volume_object prefix, uint32_t max_count, struct store_list *list) {
	char obj_name[VOLUME_OBJECT_STRING_MAX];

	volume_object_string(obj_name, prefix);
	return store_list_object(bucket_get_selected(), obj_name, max_count, list);
}

int volume_put_object(struct volume_object object, const char *buf, uint32_t len) {
	char obj_name[VOLUME_OBJECT_STRING_MAX], *pk_buf, *cr_buf;
	uint32_t pk_len, cr_len;
	int ret;

	if (!pack_compress(buf, len, &pk_buf, &pk_len))
		return SYS_ERROR;

	if (crypt_has_cipher()) {
		if (!crypt_enc(pk_buf, pk_len, &cr_buf, &cr_len)) {
			free(pk_buf);
			return SYS_ERROR;
		}
		free(pk_buf);
	}
	else {
		cr_buf = pk_buf;
		cr_len = pk_len;
	}

	volume_object_string(obj_name, object);
	ret = store_put_object(bucket_get_selected(), obj_name, cr_buf, cr_len);
	free(cr_buf);
	return ret;
}

int volume_get_object(struct volume_object object, char **buf, uint32_t *len) {
	char obj_name[VOLUME_OBJECT_STRING_MAX], *out_buf, *pk_buf, *cr_buf;
	uint32_t out_len, pk_len, cr_len;
	int ret;

	volume_object_string(obj_name, object);
	if ((ret = store_get_object(bucket_get_selected(), obj_name,
			&out_buf, &out_len)) != SUCCESS)
		return ret;

	if (crypt_has_cipher()) {
		if (!crypt_dec(out_buf, out_len, &cr_buf, &cr_len, false)) {
			free(out_buf);
			return SYS_ERROR;
		}
		free(out_buf);
	}
	else {
		cr_buf = out_buf;
		cr_len = out_len;
	}

	if (!pack_uncompress(cr_buf, cr_len, &pk_buf, &pk_len)) {
		free(cr_buf);
		return SYS_ERROR;
	}
	free(cr_buf);

	*buf = pk_buf;
	*len = pk_len;
	return SUCCESS;
}

int volume_exists_object(struct volume_object object) {
	char obj_name[VOLUME_OBJECT_STRING_MAX];

	volume_object_string(obj_name, object);
	return store_exists_object(bucket_get_selected(), obj_name);
}

int volume_delete_object(struct volume_object object) {
	char obj_name[VOLUME_OBJECT_STRING_MAX];

	volume_object_string(obj_name, object);
	return store_delete_object(bucket_get_selected(), obj_name);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object name formatting

void volume_metadata_string(char name[static VOLUME_METADATA_STRING_MAX]) {
	snprintf(name, VOLUME_METADATA_STRING_MAX, VOLUME_METADATA_PREFIX "%s",
			volume_selected);
}

void volume_lock_string(char name[static VOLUME_LOCK_STRING_MAX]) {
	snprintf(name, VOLUME_LOCK_STRING_MAX, VOLUME_LOCK_PREFIX "%s",
			volume_selected);
}

void volume_object_string(char name[static VOLUME_OBJECT_STRING_MAX],
		struct volume_object object) {
	snprintf(name, VOLUME_OBJECT_STRING_MAX, VOLUME_OBJECT_PREFIX
			"%s.%016" PRIx64 ".%016" PRIx64,
			volume_selected, object.index, object.chunk);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     File size conversion

bool volume_str_to_size(const char *str, uint64_t *size) {
	double ap;
	char *ptr;

	if ((ap = strtod(str, &ptr)) < 0)
		return false;
	for (; isspace(*ptr); ptr++);
	switch (tolower(*ptr)) {
		default: return false;
		case 'p': ap *= 1024;
		case 't': ap *= 1024;
		case 'g': ap *= 1024;
		case 'm': ap *= 1024;
		case 'k': ap *= 1024;
		case 'i':
		case 'b': break;
	}

	*size = ap;
	return true;
}

void volume_size_to_str(uint64_t size, char *str, uint32_t len) {
	static const char *suffix[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
	double ap;
	uint32_t i;

	for (ap = size, i = 0; ap > 1024 &&
			i < sizearr(suffix) - 1; ap /= 1024, i++);

	snprintf(str, len, "%.3g %s", ap, suffix[i]);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Volume selection

const char *volume_get_selected() {
	return volume_selected;
}
