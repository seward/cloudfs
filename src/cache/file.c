/*
 * cloudfs: file source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <semaphore.h>
#include "config.h"
#include "log.h"
#include "object.h"
#include "misc.h"
#include "cache/file.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       file
// Description: Memory cache medium

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache table

const struct object_cache_intr file_intr = {
	.load		= file_load,
	
	.get_max	= file_get_max,
	.get_capacity	= file_get_capacity,
	
	.create		= file_create,
	.read		= file_read,
	.write		= file_write,
	.destroy	= file_destroy,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache file counter

static sem_t file_stat_lock;

static uint64_t file_used = 0;

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache file path

static const char *file_path = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     Initialization

void file_load() {
	struct object_cache *tmp;
	struct rlimit rlim;
	uint32_t limit;
	
	sem_init(&file_stat_lock, 0, 1);
	
	limit = OBJECT_MAX_CACHE_COUNT + FILE_LIMIT_RESERVE;
	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
		stderror("getrlimit");
	if (rlim.rlim_max < limit)
		error("Open file limit must be greater than %d", limit);
	if (rlim.rlim_cur < limit) {
		rlim.rlim_cur = limit;
		if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
			stderror("setrlimit");
	}
	
	if (!(file_path = config_get("cache-path")))
		error("Must specify --cache-path");
	
	if (!(tmp = file_create()))
		error("Cache file creation failed");
	file_destroy(tmp);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Memory maximums and capacity

uint64_t file_get_max() {
	return FILE_DEFAULT_MAX;
}

uint64_t file_get_capacity() {
	uint64_t __file_used;

	sem_wait(&file_stat_lock);
	__file_used      = file_used;
	sem_post(&file_stat_lock);
	
	return __file_used;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache operations

struct object_cache *file_create() {
	struct file_cache *file;
	char *fname;
	
	if (!(file = calloc(sizeof(*file), 1)))
		stderror("calloc");
		
	asprintf(&fname, "%s/cloudfs.cache.%x.%x.%x",
			file_path, rand(), rand(), rand());
	if ((file->fd = open(fname, O_RDWR | O_CREAT, (mode_t) 0600)) < 0)
		error("Creating new cache file failed %s: %s",
				fname, strerror(errno));
	unlink(fname);
	free(fname);
	
	return (struct object_cache *) file;
}
	
int file_read(struct object_cache *cache, uint32_t offt, char *buf, uint32_t *len) {
	struct file_cache *file;
	ssize_t rlen;
	
	file = (struct file_cache *) cache;

	if ((rlen = pread(file->fd, buf, *len, offt)) < 0)
		stderror("pread");
	
	*len = rlen;
	return SUCCESS;
}
int file_write(struct object_cache *cache, uint32_t offt, const char *buf, uint32_t len) {
	struct file_cache *file;
	uint32_t new_size;
	ssize_t rlen;
	
	file = (struct file_cache *) cache;

	new_size = len + offt;
	if (new_size > file->len) {
		sem_wait(&file_stat_lock);
		file_used += new_size - file->len;
		sem_post(&file_stat_lock);
		
		file->len = new_size;
	}
	
	if ((rlen = pwrite(file->fd, buf, len, offt)) < 0)
		stderror("pread");
	return SUCCESS;
}

int file_destroy(struct object_cache *cache) {
	struct file_cache *file;
	
	file = (struct file_cache *) cache;
	
	sem_wait(&file_stat_lock);
	assert(file_used >= file->len);
	file_used -= file->len;
	sem_post(&file_stat_lock);
	
	close(file->fd);
	free(file);
	return SUCCESS;
}
