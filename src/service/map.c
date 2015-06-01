/*
 * cloudfs: map source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "service/map.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       map
// Description: Creates map object to be sent or received

////////////////////////////////////////////////////////////////////////////////
// Section:     Object creation and destruction

map_t map_new(const char *name) {
  map_t n;

  if (!(n = calloc(sizeof(*n), 1)))
    stderror("calloc");
  n->name = (name ? strdup(name) : NULL);
  if (!n->name)
    stderror("strdup");
  n->type = D_MAP_TYPE_NORMAL;
  return n;
}

void map_free(map_t p) {
  map_t r, n;

  if (!p)
    return;
  
  for (r = p->child; r;) {
    n = r->next;
    map_free(r);
    r = n;
  }
  if (p->name)
    free(p->name);
  if (p->value)
    free(p->value);
  free(p);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Adding / Removing items

void map_add(map_t p, map_t n) {
  if (!p || !n)
    return;
  n->next = NULL;
  if (p->child) {
    n->prev = p->last;
    p->last->next = n;
  } else {
    p->child = n;
  }
  p->last = n;
  n->parent = p;
}

void map_insert(map_t p, map_t n) {
  if (!p || !n)
    return;
  n->prev = NULL;
  n->next = p->child;
  if (p->child)
    p->child->prev = n;
  else
    p->last = n;
  p->child = n;
  n->parent = p;
}

map_t map_next(map_t p, const char *name) {
  if (!p)
    return NULL;
  p = p->next;
  if (name) {
    for (; p; p = p->next) {
      if (p->name && !strcasecmp(p->name, name))
        break;
    }
  }
  return p;
}

map_t map_child(map_t p, const char **name) {
  if (!p)
    return NULL;
  p = p->child;
  if (p && name)
    *name = p->name;
  return p;
}

void map_remove(map_t p) {
  map_t f;
  
  if (!p)
    return;
  if ((f = p->parent)) {
    if (p->prev)
      p->prev->next = p->next;
    else
      f->child = p->next;
    if (p->next)
      p->next->prev = p->prev;
    else
      f->last = p->prev;
  }
  map_free(p);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Deleting name / value pairs

void map_del(map_t p, const char *name) {
  map_t r;

  if (!p)
    return;
  for (p = p->child; p;) {
    r = p->next;
    if (!name || (p->name && !strcasecmp(p->name, name)))
      map_remove(p);
    p = r;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Setting name / value pairs

map_t map_set(map_t p, const char *name) {
  map_t n;

  if (!p || !(n = map_new(name)))
    return NULL;
  map_add(p, n);
  return n;
}

map_t map_set_str(map_t p, const char *name, const char *value) {
  map_t n;

  if (!(n = map_set(p, name)))
    return NULL;
  if (value) {
    if (!(n->value = strdup(value)))
      stderror("strdup");
  }
  return n;
}

map_t map_set_strn(map_t p, const char *name, const char *value, uint32_t len) {
  map_t n;

  if (!(n = map_set(p, name)))
    return NULL;
  if (!(n->value = calloc(len + 1, 1)))
    stderror("calloc");
  memcpy(n->value, value, len);
  return n;
}

map_t map_set_strf(map_t p, const char *name, const char *value, ...) {
  char *buf;
  map_t ret;
  va_list ap;

  va_start(ap, value);
  vasprintf(&buf, value, ap);
  va_end(ap);

  ret = map_set_str(p, name, buf);

  free(buf);
  return ret;
}

map_t map_set_int(map_t p, const char *name, int64_t value) {
  map_t n;

  if ((n = map_set_strf(p, name, "%"PRId64, value)))
    n->type = D_MAP_TYPE_UNESCAPED;
  return n;
}

map_t map_set_uint(map_t p, const char *name, uint64_t value) {
  map_t n;

  if ((n = map_set_strf(p, name, "%"PRIu64, value)))
    n->type = D_MAP_TYPE_UNESCAPED;
  return n;
}

map_t map_set_dbl(map_t p, const char *name, double value) {
  map_t n;

  if ((n = map_set_strf(p, name, "%f", value)))
    n->type = D_MAP_TYPE_UNESCAPED;
  return n;
}

map_t map_set_bool(map_t p, const char *name, bool value) {
  map_t n;

  if ((n = map_set_str(p, name, (value ? "true" : "false"))))
    n->type = D_MAP_TYPE_UNESCAPED;
  return n;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Getting name / value pairs

map_t map_get(map_t p, const char *name) {
  if (!p)
    return NULL;
  if (!name)
    return p;
  for (p = p->child; p; p = p->next) {
    if (!strcasecmp(p->name, name))
      break;
  }
  return p;
}

const char *map_get_str(map_t p, const char *name) {
  map_t n;

  if (!(n = map_get(p, name)))
    return NULL;
  return n->value;
}

bool map_get_strf(map_t p, const char *name, const char *value, ...) {
  va_list va;
  const char *v;

  if (!(v = map_get_str(p, name)))
    return false;

  va_start(va, value);
  vsscanf(v, value, va);
  va_end(va);
  return true;
}

int64_t map_get_int(map_t p, const char *name) {
  int64_t value;

  value = 0L;
  if (!map_get_strf(p, name, "%"PRId64, &value))
    return 0L;
  return value;
}

uint64_t map_get_uint(map_t p, const char *name) {
  uint64_t value;

  value = 0UL;
  if (!map_get_strf(p, name, "%"PRIu64, &value))
    return 0UL;
  return value;
}

double map_get_dbl(map_t p, const char *name) {
  double value;

  value = 0.0;
  if (!map_get_strf(p, name, "%lf", &value))
    return 0.0;
  return value;
}

bool map_get_bool(map_t p, const char *name) {
  const char *value;

  if (!(value = map_get_str(p, name)))
    return false;
  if (!strcmp(value, "1") ||
      !strcasecmp(value, "true") ||
      !strcasecmp(value, "yes"))
    return true;
  return false;
}

