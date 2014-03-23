/*
 * cloudfs: object header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>
#include "store.h"
#include "volume.h"
#include "trxlog.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define OBJECT_MAX_SIZE           (4 * 1024 * 1024)
#define OBJECT_MAX_SIZE_LOG2      22

#define OBJECT_MAX_HMAP           (1 << 8)

#define OBJECT_MAX_CACHE_COUNT    128

#define OBJECT_THREAD_STACK_SIZE  (1 * 1024 * 1024)

#define OBJECT_THREAD_INTERVAL    15

#define OBJECT_MD5_DIGEST_LENGTH  16

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache interface table definition

enum object_flag {
  OBJECT_CACHE_NOT_PRESENT = 1 << 0,
  OBJECT_CACHE_DIRTY       = 1 << 1,
  OBJECT_CACHE_DESTROY     = 1 << 2,
};

enum object_release_flag {
  OBJECT_RELEASE_DESTROY   = 1 << 0,
  OBJECT_RELEASE_FORCE     = 1 << 1,
};

struct object_cache {
  struct object_cache *hmap_prev, *hmap_next,
          *lru_prev, *lru_next,
          *fsh_prev, *fsh_next;
  struct trxlog trxlog;
  struct volume_object object;
  sem_t lock;
  int32_t refcount, flag;
  char md5[OBJECT_MD5_DIGEST_LENGTH];
};

struct object_cache_intr {
  void (*load)   ();
  void (*unload) ();

  uint64_t (*get_max)      ();
  uint64_t (*get_capacity) ();

  struct object_cache *(*create) ();
  int (*read)    (struct object_cache*, uint32_t, char *, uint32_t *);
  int (*write)   (struct object_cache*, uint32_t, const char *, uint32_t);
  int (*destroy) (struct object_cache*);
};

struct object_cache_intr_opt {
  const char *name;
  const struct object_cache_intr *intr;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Object initialization

void object_load();
void object_load_thread();
void object_unload();
void object_unload_thread();

////////////////////////////////////////////////////////////////////////////////
// Section:     Object interface functions

int object_read(struct volume_object object, uint32_t offt, char *buf,
                uint32_t len, uint32_t *olen);
int object_write(struct volume_object object, uint32_t offt, const char *buf,
                 uint32_t len);
int object_exists(struct volume_object object);
int object_delete(struct volume_object object);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache creation

struct object_cache *object_cache_create_and_aquire(
    struct volume_object object);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache hashmap linking

struct object_cache **object_cache_hmap_head(struct volume_object object);
void object_cache_hmap_link(struct object_cache *p);
void object_cache_hmap_unlink(struct object_cache *p);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache LRU linking

void object_cache_lru_link(struct object_cache *p);
void object_cache_lru_pushfront(struct object_cache *p);
void object_cache_lru_unlink(struct object_cache *p);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache FSH linking

void object_cache_fsh_link(struct object_cache *p);
void object_cache_fsh_unlink(struct object_cache *p);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache access management

struct object_cache *object_cache_lookup_and_acquire(
    struct volume_object object);
void object_cache_acquire(struct object_cache *p);
void object_cache_lock(struct object_cache *p);
void object_cache_unlock(struct object_cache *p);
void object_cache_release(struct object_cache *p, int32_t flag);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache fulfilling and flushing

void object_cache_mark_dirty(struct object_cache *p);
void object_cache_mark_clean(struct object_cache *p);
void object_cache_mark_present(struct object_cache *p);
int object_cache_fulfill(struct object_cache *p);
int object_cache_flush(struct object_cache *p);
void object_cache_garbage_collect(uint32_t needed);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache destruction

void object_cache_destroy(struct object_cache *p);

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache thread

void object_cache_thread(void *__unused);
bool object_cache_thread_fulfill(bool *queue_empty);
