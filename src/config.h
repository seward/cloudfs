/*
 * cloudfs: config header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdbool.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define CONFIG_MAX_LINE		(1 << 9)

#define CONFIG_DEFAULT_FILE	"cloudfs.conf"
#define CONFIG_DEFAULT_GROUP	"cloudfs"

////////////////////////////////////////////////////////////////////////////////
// Section:     Structs

typedef struct config_var {
	char *name, *value;
	struct config_var *next;
} *config_var;

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

bool config_default();

bool config_load(const char *fname);
void config_unload();

void config_set(const char *name, const char *value);
const char *config_get(const char *name);
