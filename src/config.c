/*
 * cloudfs: config source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include "config.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       config
// Description: Parses config file

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static config_var config_list = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     Initializiation

bool config_default() {
	char *home_path;
	bool ret;

	if (asprintf(&home_path, "%s/." CONFIG_DEFAULT_FILE, getenv("HOME")) < 0)
		stderror("asprintf");

	ret =  (config_load(home_path) ||
		config_load("/etc/" CONFIG_DEFAULT_FILE) ||
		config_load("/usr/local/etc/" CONFIG_DEFAULT_FILE) ||
		config_load(CONFIG_DEFAULT_FILE));

	free(home_path);
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Loading

static char *strtrim(char *src) {
	uint32_t len;

	len = strlen(src);
	while (len && isspace(src[len - 1]))
		src[--len] = 0;
	while (isspace(*src))
		src++;
	return src;
}

bool config_load(const char *fname) {
	char buf[CONFIG_MAX_LINE], group[CONFIG_MAX_LINE],
		fullname[(CONFIG_MAX_LINE * 2) + 2], *name, *ptr;
	FILE *f;
	bool have_group;

	if (!(f = fopen(fname, "r")))
		return false;

	have_group = false;
	while(1) {
		if (!fgets(buf, sizeof(buf), f))
			break;

		ptr = strtrim(buf);
		switch (*ptr) {
			case '#':
				break;

			case '[':
				ptr = strtrim(ptr + 1);

				for (name = ptr; *ptr && *ptr != ']'; ptr++);
				if (*ptr)
					*ptr++ = 0;

				strcpy(group, strtrim(name));
				if (!strcmp(group, CONFIG_DEFAULT_GROUP))
					have_group = false;
				else
					have_group = true;
				break;

			default:
				for (name = ptr; *ptr && *ptr != '='; ptr++);
				if (*ptr)
					*ptr++ = 0;

				ptr = strtrim(ptr);
				name = strtrim(name);
				if (!*name)
					break;

				if (have_group) {
					snprintf(fullname, sizeof(fullname), "%s-%s", group, name);
					config_set(fullname, ptr);
				}
				else
					config_set(name, ptr);
				break;
		}
	}
	fclose(f);
	return true;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Unloading configuration

void config_unload() {
	config_var cv;

	while (config_list) {
		cv = config_list;
		config_list = cv->next;

		if (cv->name)
			free(cv->name);
		if (cv->value)
			free(cv->value);
		free(cv);
	}
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Setting

void config_set(const char *name, const char *value) {
	config_var cv;

	assert(name != NULL && value != NULL);

	for (cv = config_list; cv; cv = cv->next) {
		if (!strcasecmp(cv->name, name)) {
			free(cv->value);
			break;
		}
	}

	if (!cv) {
		if (!(cv = calloc(sizeof(*cv), 1)))
			stderror("calloc");
		if (!(cv->name = strdup(name)))
			stderror("strdup");
		cv->next = config_list;
		config_list = cv;
	}
	if (!(cv->value = strdup(value)))
		stderror("strdup");
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Searching

const char *config_get(const char *name) {
	config_var cv;

	assert(name != NULL);

	for (cv = config_list; cv; cv = cv->next) {
		if (!strcasecmp(cv->name, name))
			return cv->value;
	}
	return NULL;
}
