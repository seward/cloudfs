/*
 * cloudfs: object source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <inttypes.h>
#include <openssl/md5.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "volume.h"
#include "object.h"
#include "trxlog.h"
#include "cache/memory.h"
#include "cache/file.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       object
// Description: Object management for storage interface

////////////////////////////////////////////////////////////////////////////////
// Section:     Available object cache mediums

static const struct object_cache_intr_opt object_cache_intr_opt_list[] = {
  { "memory", &memory_intr },
  {   "file", &file_intr   },
};

static const struct object_cache_intr *object_cache_intr_ptr = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     List of cache data

static struct object_cache *object_cache_lru_head = NULL,
                           *object_cache_lru_tail = NULL,
                           *object_cache_fsh_head = NULL,
                           *object_cache_fsh_tail = NULL,
                           *object_cache_hmap[OBJECT_MAX_HMAP] = { };

static sem_t object_cache_global_lock;

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache thread

static pthread_t object_cache_thread_id;

static sem_t object_cache_thread_wake,
             object_cache_thread_flushed;

static bool object_cache_thread_running = false;

////////////////////////////////////////////////////////////////////////////////
// Section:     Cache memory limits

static uint64_t object_cache_max = 0,
                object_cache_count = 0;

static sem_t object_cache_count_lock;

////////////////////////////////////////////////////////////////////////////////
// Section:     Object construction / destruction

void object_load() {
  const struct object_cache_intr_opt *opt, *opt_end;
  const char *cache, *cmax;

  if (OBJECT_MD5_DIGEST_LENGTH != MD5_DIGEST_LENGTH)
    error("MD5 digest length does not match that of OpenSSL");

  sem_init(&object_cache_global_lock, 0, 1);
  sem_init(&object_cache_count_lock, 0, 1);

  if (!(cache = config_get("cache-type")))
    cache = "memory";

  for (opt = object_cache_intr_opt_list,
       opt_end = opt + sizearr(object_cache_intr_opt_list);
       opt < opt_end;
       opt++) {
    if (!strcasecmp(cache, opt->name)) {
      object_cache_intr_ptr = opt->intr;
      break;
    }
  }

  if (!object_cache_intr_ptr)
    error("Invalid cache specified");

  if (object_cache_intr_ptr->load)
    object_cache_intr_ptr->load();

  if ((cmax = config_get("cache-max"))) {
    volume_str_to_size(cmax, &object_cache_max);
  } else {
    if (!object_cache_intr_ptr->get_max)
      error("Must specify --cache-max for selected cache type");

    object_cache_max = object_cache_intr_ptr->get_max();
    if (object_cache_max < OBJECT_MAX_SIZE) {
      char max_size[1 << 7];

      volume_size_to_str(OBJECT_MAX_SIZE, max_size, sizeof(max_size));
      error("Cache max must be at minimum %s", max_size);
    }
  }

  object_load_thread();
}

void object_load_thread() {
  pthread_attr_t pattr;
  int ret;

  sem_init(&object_cache_thread_wake, 0, 0);
  sem_init(&object_cache_thread_flushed, 0, 0);

  object_cache_thread_running = true;

  pthread_attr_init(&pattr);
  pthread_attr_setstacksize(&pattr, OBJECT_THREAD_STACK_SIZE);
  ret = pthread_create(&object_cache_thread_id, &pattr,
                       (void *(*)(void*)) object_cache_thread, NULL);
  pthread_attr_destroy(&pattr);

  if (ret < 0)
    error("Error creating cache thread");
}

void object_unload() {
  object_unload_thread();

  if (object_cache_intr_ptr && object_cache_intr_ptr->unload)
    object_cache_intr_ptr->unload();
  object_cache_intr_ptr = NULL;
}

void object_unload_thread() {
  notice("Flushing cache...");
  if (object_cache_thread_running) {
    object_cache_thread_running = false;
    sem_post(&object_cache_thread_wake);
    pthread_join(object_cache_thread_id, NULL);
  }
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object interface functions

int object_read(struct volume_object object, uint32_t offt, char *buf,
                uint32_t len, uint32_t *olen) {
  struct object_cache *p;
  uint32_t rlen;
  int ret;

  assert(offt + len <= OBJECT_MAX_SIZE);

  p = object_cache_create_and_aquire(object);
  object_cache_lock(p);

  if ((p->flag & OBJECT_CACHE_NOT_PRESENT) &&
      !trxlog_match(&p->trxlog, offt, len)) {
    if ((ret = object_cache_fulfill(p)) != SUCCESS)
      goto out;
  }

  rlen = len;
  if ((ret = object_cache_intr_ptr->read(p, offt, buf, &rlen)) != SUCCESS)
    goto out;

  if (olen)
    *olen = rlen;
  else if (rlen < len)
    memset(buf + rlen, 0, len - rlen);
  ret = SUCCESS;

out:
  object_cache_lru_pushfront(p);
  object_cache_unlock(p);
  object_cache_release(p, 0);
  return ret;
}

int object_write(struct volume_object object, uint32_t offt, const char *buf,
                 uint32_t len) {
  struct object_cache *p;
  int ret;

  assert(offt + len <= OBJECT_MAX_SIZE);

  p = object_cache_create_and_aquire(object);
  object_cache_lock(p);

  if ((ret = object_cache_intr_ptr->write(p, offt, buf, len)) != SUCCESS)
    goto out;

  if ((p->flag & OBJECT_CACHE_NOT_PRESENT))
    trxlog_add(&p->trxlog, offt, len);
  object_cache_mark_dirty(p);

  ret = SUCCESS;

out:
  object_cache_lru_pushfront(p);
  object_cache_unlock(p);
  object_cache_release(p, 0);
  return ret;
}

int object_exists(struct volume_object object) {
  struct object_cache *p;

  if ((p = object_cache_lookup_and_acquire(object))) {
    object_cache_release(p, 0);
    return SUCCESS;
  }

  return volume_exists_object(object);
}

int object_delete(struct volume_object object) {
  struct object_cache *p;
  int ret;
  bool in_cache;

  if ((p = object_cache_lookup_and_acquire(object))) {
    in_cache = true;
    object_cache_release(p, OBJECT_RELEASE_DESTROY |
                         OBJECT_RELEASE_FORCE);
  } else {
    in_cache = false;
  }

  if ((ret = volume_delete_object(object)) == NOT_FOUND) {
    if (in_cache)
      ret = SUCCESS;
  }
  return ret;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache creation

static inline bool object_equals(struct volume_object a,
                                 struct volume_object b) {
  return (a.index == b.index && a.chunk == b.chunk);
}

struct object_cache *object_cache_create_and_aquire(
    struct volume_object object) {
  struct object_cache *p;

  object_cache_garbage_collect(OBJECT_MAX_SIZE);

  sem_wait(&object_cache_global_lock);

  for (p = *object_cache_hmap_head(object); p; p = p->hmap_next) {
    if (object_equals(p->object, object)) {
      object_cache_acquire(p);
      break;
    }
  }

  if (!p) {
    if (!(p = object_cache_intr_ptr->create()))
      error("Cache creation failure");

    p->object = object;
    p->refcount = 1;
    p->flag = OBJECT_CACHE_NOT_PRESENT;
    sem_init(&p->lock, 0, 1);

    sem_wait(&object_cache_count_lock);
    object_cache_count++;
    sem_post(&object_cache_count_lock);

    object_cache_lru_link(p);
    object_cache_hmap_link(p);
  }

  sem_post(&object_cache_global_lock);
  return p;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache hashmap linking

struct object_cache **object_cache_hmap_head(struct volume_object object) {
  return &object_cache_hmap[(object.index ^ object.chunk) % OBJECT_MAX_HMAP];
}

void object_cache_hmap_link(struct object_cache *p) {
  struct object_cache **head;

  head = object_cache_hmap_head(p->object);

  p->hmap_prev = NULL;
  p->hmap_next = *head;
  if (*head)
    (*head)->hmap_prev = p;
  *head = p;
}

void object_cache_hmap_unlink(struct object_cache *p) {
  struct object_cache **head;

  head = object_cache_hmap_head(p->object);

  if (p->hmap_prev)
    p->hmap_prev->hmap_next = p->hmap_next;
  else
    *head = p->hmap_next;
  if (p->hmap_next)
    p->hmap_next->hmap_prev = p->hmap_prev;

  p->hmap_next = NULL;
  p->hmap_prev = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache LRU linking

void object_cache_lru_link(struct object_cache *p) {
  p->lru_prev = NULL;
  p->lru_next = object_cache_lru_head;
  if (object_cache_lru_head)
    object_cache_lru_head->lru_prev = p;
  else
    object_cache_lru_tail = p;
  object_cache_lru_head = p;
}

void object_cache_lru_pushfront(struct object_cache *p) {
  sem_wait(&object_cache_global_lock);

  object_cache_lru_unlink(p);
  object_cache_lru_link(p);

  sem_post(&object_cache_global_lock);
}

void object_cache_lru_unlink(struct object_cache *p) {
  if (p->lru_prev)
    p->lru_prev->lru_next = p->lru_next;
  else
    object_cache_lru_head = p->lru_next;
  if (p->lru_next)
    p->lru_next->lru_prev = p->lru_prev;
  else
    object_cache_lru_tail = p->lru_prev;

  p->lru_next = NULL;
  p->lru_prev = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache FSH linking

void object_cache_fsh_link(struct object_cache *p) {
  p->fsh_next = NULL;
  if (!object_cache_fsh_head) {
    object_cache_fsh_head = p;
  } else {
    p->fsh_prev = object_cache_fsh_tail;
    object_cache_fsh_tail->fsh_next = p;
  }
  object_cache_fsh_tail = p;
}

void object_cache_fsh_unlink(struct object_cache *p) {
  if (p->fsh_prev)
    p->fsh_prev->fsh_next = p->fsh_next;
  else
    object_cache_fsh_head = p->fsh_next;
  if (p->fsh_next)
    p->fsh_next->fsh_prev = p->fsh_prev;
  else
    object_cache_fsh_tail = p->fsh_prev;

  p->fsh_next = NULL;
  p->fsh_prev = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache access management

struct object_cache *object_cache_lookup_and_acquire(
    struct volume_object object) {
  struct object_cache *p;

  sem_wait(&object_cache_global_lock);

  for (p = *object_cache_hmap_head(object); p; p = p->hmap_next) {
    if (object_equals(p->object, object)) {
      object_cache_acquire(p);
      break;
    }
  }

  sem_post(&object_cache_global_lock);
  return p;
}

void object_cache_acquire(struct object_cache *p) {
  p->refcount++;
}

void object_cache_release(struct object_cache *p, int32_t flag) {
  sem_wait(&object_cache_global_lock);

  if (p->refcount)
    p->refcount--;
  if ((flag & OBJECT_RELEASE_DESTROY))
    p->flag |= OBJECT_CACHE_DESTROY;

  if (!p->refcount && (p->flag & OBJECT_CACHE_DESTROY) &&
      ((flag & OBJECT_RELEASE_FORCE) || !(p->flag & OBJECT_CACHE_DIRTY)))
    object_cache_destroy(p);

  sem_post(&object_cache_global_lock);
}

void object_cache_lock(struct object_cache *p) {
  sem_wait(&p->lock);
}

void object_cache_unlock(struct object_cache *p) {
  sem_post(&p->lock);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache fulfilling and flushing

void object_cache_mark_dirty(struct object_cache *p) {
  if ((p->flag & OBJECT_CACHE_DIRTY))
    return;
  p->flag |= OBJECT_CACHE_DIRTY;

  sem_wait(&object_cache_global_lock);
  object_cache_fsh_link(p);
  sem_post(&object_cache_global_lock);
}

void object_cache_mark_clean(struct object_cache *p) {
  if (!(p->flag & OBJECT_CACHE_DIRTY))
    return;
  p->flag &= ~OBJECT_CACHE_DIRTY;

  sem_wait(&object_cache_global_lock);
  object_cache_fsh_unlink(p);
  sem_post(&object_cache_global_lock);
}

void object_cache_mark_present(struct object_cache *p) {
  p->flag &= ~OBJECT_CACHE_NOT_PRESENT;
}

int object_cache_fulfill(struct object_cache *p) {
  char *rbuf, *sbuf;
  uint32_t rlen, len, from, to;
  int ret;
  bool mark;

  if (!(p->flag & OBJECT_CACHE_NOT_PRESENT))
    return SUCCESS;

  if (trxlog_match(&p->trxlog, 0, OBJECT_MAX_SIZE))
    goto out;

  ret = volume_get_object(p->object, &rbuf, &rlen);
  if (ret == NOT_FOUND)
    goto out;
  if (ret != SUCCESS)
    return ret;

  sbuf = rbuf;

  if (rlen >= OBJECT_MD5_DIGEST_LENGTH) {
    memcpy(p->md5, sbuf, OBJECT_MD5_DIGEST_LENGTH);

    sbuf += OBJECT_MD5_DIGEST_LENGTH;
    rlen -= OBJECT_MD5_DIGEST_LENGTH;
  }

  from = 0;
  to = rlen;
  while (from < to) {
    trxlog_list(&p->trxlog, from, to, &len, &mark);

    if (!mark && (ret =
            object_cache_intr_ptr->write(p, from, sbuf, len)) != SUCCESS) {
      free(rbuf);
      warning("Write error onto cache object");
      return ret;
    }

    from += len;
    sbuf += len;
  }

  free(rbuf);

out:
  object_cache_mark_present(p);
  return SUCCESS;
}

int object_cache_flush(struct object_cache *p) {
  char new_md5[OBJECT_MD5_DIGEST_LENGTH];
  char *buf, *rbuf;
  uint32_t len, rlen;
  int ret;

  if (!(p->flag & OBJECT_CACHE_DIRTY))
    return SUCCESS;

  if ((p->flag & OBJECT_CACHE_NOT_PRESENT)) {
    ret = object_cache_fulfill(p);
    if (ret != SUCCESS && ret != NOT_FOUND)
      return ret;
  }

  if (!(buf = malloc(OBJECT_MD5_DIGEST_LENGTH + OBJECT_MAX_SIZE)))
    stderror("malloc");

  rbuf = buf + OBJECT_MD5_DIGEST_LENGTH;
  len = 0;
  while (len < OBJECT_MAX_SIZE) {
    rlen = OBJECT_MAX_SIZE - len;
    if ((ret = object_cache_intr_ptr->read(p, len, rbuf + len,
                                           &rlen)) != SUCCESS) {
      free(buf);
      return ret;
    }
    if (!rlen)
      break;
    len += rlen;
  }

  MD5((uint8_t*) rbuf, len, (uint8_t*) new_md5);
  if (memcmp(new_md5, p->md5, OBJECT_MD5_DIGEST_LENGTH) != 0) {
    memcpy(p->md5, new_md5, OBJECT_MD5_DIGEST_LENGTH);
    memcpy(buf,    new_md5, OBJECT_MD5_DIGEST_LENGTH);

    if ((ret = volume_put_object(p->object, buf,
                                 OBJECT_MD5_DIGEST_LENGTH + len)) != SUCCESS) {
      free(buf);
      return ret;
    }
  }
  free(buf);

  object_cache_mark_clean(p);
  return SUCCESS;
}

void object_cache_garbage_collect(uint32_t needed) {
  struct object_cache *p;

  assert(needed <= object_cache_max);

  while (object_cache_intr_ptr->get_capacity() + needed > object_cache_max ||
         object_cache_count > OBJECT_MAX_CACHE_COUNT) {
    sem_wait(&object_cache_global_lock);

    for (p = object_cache_lru_tail; p; p = p->lru_prev) {
      if (!(p->flag & OBJECT_CACHE_DIRTY) &&
          !(p->flag & OBJECT_CACHE_DESTROY)) {
        object_cache_acquire(p);
        break;
      }
    }

    sem_post(&object_cache_global_lock);

    if (p) {
      object_cache_release(p, OBJECT_RELEASE_DESTROY);
      continue;
    }

    sem_post(&object_cache_thread_wake);
    sem_wait(&object_cache_thread_flushed);
  }
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache destruction

void object_cache_destroy(struct object_cache *p) {
  sem_wait(&object_cache_count_lock);
  object_cache_count--;
  sem_post(&object_cache_count_lock);

  object_cache_lru_unlink(p);
  object_cache_hmap_unlink(p);
  if ((p->flag & OBJECT_CACHE_DIRTY))
    object_cache_fsh_unlink(p);

  trxlog_free(&p->trxlog);
  object_cache_intr_ptr->destroy(p);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Object cache thread

void object_cache_thread(void *__unused) {
  struct timespec tm;
  uint32_t interval;
  bool want_post, queue_empty;

  interval = 0;
  queue_empty = false;
  while (object_cache_thread_running || !queue_empty) {
    clock_gettime(CLOCK_REALTIME, &tm);
    tm.tv_sec += interval;
    if (sem_timedwait(&object_cache_thread_wake, &tm) < 0)
      want_post = false;
    else
      want_post = true;

    if (!object_cache_thread_fulfill(&queue_empty) &&
        object_cache_thread_running)
      interval = OBJECT_THREAD_INTERVAL;
    else
      interval = 0;

    if (want_post)
      sem_post(&object_cache_thread_flushed);
  }
}

bool object_cache_thread_fulfill(bool *queue_empty) {
  struct object_cache *p;
  int ret;

  sem_wait(&object_cache_global_lock);

  if ((p = object_cache_fsh_head))
    object_cache_acquire(p);
  if (!p || !p->fsh_next)
    *queue_empty = true;
  else
    *queue_empty = false;

  sem_post(&object_cache_global_lock);

  if (!p)
    return false;

  object_cache_lock(p);
  ret = object_cache_flush(p);
  object_cache_unlock(p);

  object_cache_release(p, 0);

  if (ret != SUCCESS) {
    warning("Error flushing cache: %d", ret);
    return false;
  }
  return true;
}
