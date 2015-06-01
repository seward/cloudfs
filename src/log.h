/*
 * cloudfs: log header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#ifdef _DEBUG

#define debug(f, x...) \
  log_write("DEBUG (%s:%d): " f, __BASE_FILE__, __LINE__, ##x)

#define warning(f, x...) \
  log_write("WARNING (%s:%d): " f, __BASE_FILE__, __LINE__, ##x)

#define error(f, x...)                                            \
  do {                                                            \
    log_write("ERROR (%s:%d): " f, __BASE_FILE__, __LINE__, ##x); \
    exit(1);                                                      \
  } while (0)

#else

#define debug(f, x...)

#define warning(f, x...) log_write("WARNING: " f, ##x)

#define error(f, x...)           \
  do {                           \
    log_write("ERROR: " f, ##x); \
    exit(1);                     \
  } while (0)

#endif

#define notice(x...) log_write(x)

#define stderror(f) error(f ": %s", strerror(errno))

#define stdwarning(f) error(f ": %s", strerror(errno))

#ifdef assert
#undef assert
#endif

#define assert(x)                                                          \
  do {                                                                     \
    if (!(x)) {                                                            \
      log_write("ASSERT (%s:%d): Assertion failure \"%s\"", __BASE_FILE__, \
                __LINE__, #x);                                             \
      exit(1);                                                             \
    }                                                                      \
  } while (0)

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

void log_load(char *fname);

void log_write(const char *str, ...) __attribute__((format(printf, 1, 2)));

