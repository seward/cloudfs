/*
 * cloudfs: map header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define D_MAP_MAX_TREE  32

#define map_foreach(__child, __parent, __name)   \
  for (__child = map_get(__parent, __name),      \
      __child = __child ? __child->child : NULL; \
       __child; __child = __child->next)

#define map_foreach_under(__child, __parent, __name) \
  for (__child = map_get(__parent, __name); __child; \
       __child = map_next(__child, __name))

////////////////////////////////////////////////////////////////////////////////
// Section:     Typedefs / Structs

enum map_type {
  D_MAP_TYPE_NORMAL,
  D_MAP_TYPE_UNESCAPED,
  D_MAP_TYPE_NULL,
};

typedef struct map_t {
  char *name, *value;
  enum map_type type;

  struct map_t *child, *parent, *prev, *next, *last;
} *map_t;

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

map_t map_new(const char *name);
void map_free(map_t p);

void map_add(map_t p, map_t n);
void map_insert(map_t p, map_t n);
map_t map_next(map_t p, const char *name);
map_t map_child(map_t p, const char **name);
void map_remove(map_t p);

void map_del(map_t p, const char *name);

map_t map_set(map_t p, const char *name);
map_t map_set_str(map_t p, const char *name, const char *value);
map_t map_set_strn(map_t p, const char *name, const char *value, uint32_t len);
map_t map_set_strf(map_t p, const char *name, const char *value, ...);
map_t map_set_int(map_t p, const char *name, int64_t value);
map_t map_set_uint(map_t p, const char *name, uint64_t value);
map_t map_set_dbl(map_t p, const char *name, double value);
map_t map_set_bool(map_t p, const char *name, bool value);

map_t       map_get(map_t p, const char *name);
const char *map_get_str(map_t p, const char *name);
bool        map_get_strf(map_t p, const char *name, const char *value, ...);
int64_t     map_get_int(map_t p, const char *name);
uint64_t    map_get_uint(map_t p, const char *name);
double      map_get_dbl(map_t p, const char *name);
bool        map_get_bool(map_t p, const char *name);
