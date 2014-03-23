/*
 * cloudfs: store source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "store.h"
#include "service/dummy.h"
#include "service/amazon.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       store
// Description: Storage interface

////////////////////////////////////////////////////////////////////////////////
// Section:     Available storage services

static const struct store_intr_opt store_intr_opt_list[] = {
  {  "dummy", &dummy_intr  },
  { "amazon", &amazon_intr },
};

static const struct store_intr *store_intr_ptr = NULL;

static bool store_readonly = false;

////////////////////////////////////////////////////////////////////////////////
// Section:     Storage construction / destruction

void store_load() {
  const char *intr;
  const struct store_intr_opt *opt, *opt_end;

  if (!(intr = config_get("store")))
    error("Storage service must be specified using --store");

  if (config_get("readonly"))
    store_readonly = true;

  store_intr_ptr = NULL;
  for (opt = store_intr_opt_list,
       opt_end = opt + sizearr(store_intr_opt_list);
       opt < opt_end;
       opt++) {
    if (!strcasecmp(intr, opt->name)) {
      store_intr_ptr = opt->intr;
      break;
    }
  }

  if (!store_intr_ptr)
    error("Invalid storage service specified \"%s\"", intr);

  if (store_intr_ptr->load)
    store_intr_ptr->load();
}

void store_unload() {
  if (store_intr_ptr && store_intr_ptr->unload)
    store_intr_ptr->unload();
  store_intr_ptr = NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Storage interface functions

int store_list_bucket(const char *prefix, uint32_t max_count,
                      struct store_list *list) {
  return store_intr_ptr->list_bucket(prefix, max_count, list);
}

int store_create_bucket(const char *bucket) {
  assert(bucket != NULL);
  return store_intr_ptr->create_bucket(bucket);
}

int store_exists_bucket(const char *bucket) {
  assert(bucket != NULL);
  return store_intr_ptr->exists_bucket(bucket);
}

int store_delete_bucket(const char *bucket) {
  assert(bucket != NULL);
  return store_intr_ptr->delete_bucket(bucket);
}

int store_list_object(const char *bucket, const char *prefix,
                      uint32_t max_count, struct store_list *list) {
  assert(bucket != NULL);
  return store_intr_ptr->list_object(bucket, prefix, max_count, list);
}

int store_put_object(const char *bucket, const char *object,
                     const char *buf, uint32_t len) {
  assert(bucket != NULL && object != NULL);
  return store_intr_ptr->put_object(bucket, object, buf, len);
}

int store_get_object(const char *bucket, const char *object,
                     char **buf, uint32_t *len) {
  assert(bucket != NULL && object != NULL);
  return store_intr_ptr->get_object(bucket, object, buf, len);
}

int store_exists_object(const char *bucket, const char *object) {
  assert(bucket != NULL && object != NULL);
  return store_intr_ptr->exists_object(bucket, object);
}

int store_delete_object(const char *bucket, const char *object) {
  assert(bucket != NULL && object != NULL);
  return store_intr_ptr->delete_object(bucket, object);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Store list functions

struct store_list *store_list_new() {
  struct store_list *list;

  if (!(list = calloc(sizeof(*list), 1)))
    stderror("calloc");
  return list;
}

void store_list_push(struct store_list *list, const char *item) {
  if (!(list->item = realloc(list->item, sizeof(*list->item) *
                                         (list->size + 1))))
    stderror("realloc");
  if (!(list->item[list->size++] = strdup(item)))
    stderror("strdup");
}

void store_list_free(struct store_list *list) {
  uint32_t i;

  for (i = 0; i < list->size; i++)
    free(list->item[i]);
  free(list);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Store flags

bool store_get_readonly() {
  return store_readonly;
}
