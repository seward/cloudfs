/*
 * cloudfs: bucket source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "bucket.h"
#include "store.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       bucket
// Description: Bucket management for storage interface

////////////////////////////////////////////////////////////////////////////////
// Section:     Bucket operations

static const struct bucket_oper bucket_oper_list[] = {
	{ "create-bucket", bucket_create },
	{  "list-buckets", bucket_list   },
	{ "delete-bucket", bucket_delete },
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Selected bucket

static const char *bucket_selected;

////////////////////////////////////////////////////////////////////////////////
// Section:     Bucket construction / destruction

void bucket_load() {
	const struct bucket_oper *oper, *oper_end;
	const char *bucket;

	if ((bucket = config_get("bucket")))
		bucket_selected = bucket;

	for (oper = bucket_oper_list,
	     oper_end = oper + sizearr(bucket_oper_list);
	     oper < oper_end;
	     oper++) {
		if (config_get(oper->name)) {
			oper->func();
			exit(0);
		}
	}

	if (!bucket_selected)
		error("Bucket must be specified using --bucket");

	if (store_exists_bucket(bucket_selected) != SUCCESS) {
		if (config_get("auto-create-bucket")) {
			if (store_create_bucket(bucket_selected) != SUCCESS)
				error("Unable to create bucket \"%s\"", bucket_selected);
		}
		else
			error("Unable to access bucket \"%s\", try --create-bucket",
					bucket_selected);
	}
}

void bucket_unload() {
	bucket_selected = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Bucket operation functions

void bucket_create() {
	if (!bucket_selected)
		error("Must specify a --bucket for --create-bucket");

	if (store_create_bucket(bucket_selected) != SUCCESS)
		error("Unable to create bucket \"%s\"", bucket_selected);

	notice("Bucket \"%s\" has been created", bucket_selected);
}

void bucket_list() {
	struct store_list *list;
	uint32_t i;

	list = store_list_new();

	if (store_list_bucket(NULL, BUCKET_MAX, list) != SUCCESS)
		error("Unable to list buckets");

	notice("List of buckets:");
	for (i = 0; i < list->size; i++)
		notice("  %s", list->item[i]);

	store_list_free(list);
}

void bucket_delete() {
	if (!bucket_selected)
		error("Must specify a --bucket for --delete-bucket");

	if (store_delete_bucket(bucket_selected) != SUCCESS)
		error("Unable to delete bucket \"%s\"", bucket_selected);

	notice("Bucket \"%s\" has been deleted", bucket_selected);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Bucket selection

const char *bucket_get_selected() {
	return bucket_selected;
}
