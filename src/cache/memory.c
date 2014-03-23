/*
 * cloudfs: memory source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <semaphore.h>
#include "config.h"
#include "log.h"
#include "object.h"
#include "misc.h"
#include "cache/memory.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       memory
// Description: Memory cache medium

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache table

const struct object_cache_intr memory_intr = {
  .load         = memory_load,

  .get_max      = memory_get_max,
  .get_capacity = memory_get_capacity,

  .create       = memory_create,
  .read         = memory_read,
  .write        = memory_write,
  .destroy      = memory_destroy,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache memory counter

static sem_t memory_stat_lock;

static uint64_t memory_used = 0;

////////////////////////////////////////////////////////////////////////////////
// Section:     Initialization

void memory_load() {
  sem_init(&memory_stat_lock, 0, 1);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Memory maximums and capacity

uint64_t memory_get_max() {
  return MEMORY_DEFAULT_MAX;
}

uint64_t memory_get_capacity() {
  uint64_t __memory_used;

  sem_wait(&memory_stat_lock);
  __memory_used = memory_used;
  sem_post(&memory_stat_lock);

  return __memory_used;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache operations

struct object_cache *memory_create() {
  struct memory_cache *mem;

  if (!(mem = calloc(sizeof(*mem), 1)))
    stderror("calloc");
  return (struct object_cache *) mem;
}

int memory_read(struct object_cache *cache, uint32_t offt, char *buf,
                uint32_t *len) {
  struct memory_cache *mem;
  uint32_t rlen;

  mem = (struct memory_cache *) cache;

  if (offt >= mem->len)
    rlen = 0;
  else
    rlen = min(mem->len - offt, *len);

  if (rlen)
    memcpy(buf, mem->data + offt, rlen);

  *len = rlen;
  return SUCCESS;
}
int memory_write(struct object_cache *cache, uint32_t offt, const char *buf,
                 uint32_t len) {
  struct memory_cache *mem;
  uint32_t rlen;

  mem = (struct memory_cache *) cache;

  rlen = len + offt;
  if (rlen > mem->len) {
    sem_wait(&memory_stat_lock);
    memory_used += rlen - mem->len;
    sem_post(&memory_stat_lock);

    if (!(mem->data = realloc(mem->data, rlen)))
      stderror("realloc");
    mem->len = rlen;
  }

  memcpy(mem->data + offt, buf, len);
  return SUCCESS;
}

int memory_destroy(struct object_cache *cache) {
  struct memory_cache *mem;

  mem = (struct memory_cache *) cache;

  sem_wait(&memory_stat_lock);
  assert(memory_used >= mem->len);
  memory_used -= mem->len;
  sem_post(&memory_stat_lock);

  if (mem->data)
    free(mem->data);
  free(mem);
  return SUCCESS;
}
