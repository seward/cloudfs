/*
 * cloudfs: log source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <execinfo.h>
#include <errno.h>
#include <unistd.h>
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       log
// Description: Logging to file

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static FILE *log_file = NULL;

static sem_t log_lock;

static bool log_has_lock = false;

////////////////////////////////////////////////////////////////////////////////
// Section:     Initialization

void log_load(char *fname) {
  if (!(log_file = fopen(fname, "ae")))
    error("Failed to open log file \"%s\"", fname);
  fcntl(fileno(log_file), F_SETFD, FD_CLOEXEC);

  sem_init(&log_lock, 0, 1);
  log_has_lock = true;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Write to log

void log_write(const char *str, ...) {
  va_list args;
  char time_str[1<<8], *buf, *tok, *ptr;
  bool first, timestamp;
  time_t t;
  struct tm tm;

  va_start(args, str);
  if (vasprintf(&buf, str, args) < 0 || !buf)
    stderror("vasprintf");
  va_end(args);

  if (!log_file)
    log_file = stderr;

  if (isatty(fileno(log_file)))
    timestamp = false;
  else
    timestamp = true;

  if (log_has_lock)
    sem_wait(&log_lock);

  if (timestamp) {
    t = time(NULL);
    localtime_r(&t, &tm);
    strftime(time_str, sizeof(time_str), "%F %T", &tm);

    ptr = NULL;
    for (first = true, tok = strtok_r(buf, "\n", &ptr);
         tok; tok = strtok_r(NULL, "\n", &ptr), first = false)
      fprintf(log_file, "%-19s | %s\n", (first ? time_str : ""), tok);
  } else {
    fputs(buf, log_file);
    fputs("\n", log_file);
  }
  fflush(log_file);

  if (log_has_lock)
    sem_post(&log_lock);

  free(buf);
}
