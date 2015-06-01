/*
 * cloudfs: dummy source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "log.h"
#include "service/dummy.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       dummy
// Description: Dummy storage service

////////////////////////////////////////////////////////////////////////////////
// Section:     Service table

const struct store_intr dummy_intr = {
  .load           = dummy_load,

  .create_bucket  = dummy_create_bucket,
  .exists_bucket  = dummy_exists_bucket,
  .delete_bucket  = dummy_delete_bucket,

  .list_object    = dummy_list_object,
  .put_object     = dummy_put_object,
  .get_object     = dummy_get_object,
  .exists_object  = dummy_exists_object,
  .delete_object  = dummy_delete_object,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static const char *dummy_path = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     Load

void dummy_load() {
  if (!(dummy_path = config_get("dummy-path")))
    error("Must specify --dummy-path");
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Buckets

int dummy_create_bucket(const char *bucket) {
  char fname[DUMMY_MAX_PATH];

  assert(bucket != NULL);

  if (strchr(bucket, '/')) {
    warning("Bucket contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s", dummy_path, bucket);
  if (mkdir(fname, DUMMY_DIR_PERM) < 0) {
    if (errno == EEXIST)
      return SUCCESS;
    stdwarning("mkdir");
    return SYS_ERROR;
  }
  return SUCCESS;
}

int dummy_exists_bucket(const char *bucket) {
  char fname[DUMMY_MAX_PATH];
  struct stat st;

  assert(bucket != NULL);

  if (strchr(bucket, '/')) {
    warning("Bucket contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s", dummy_path, bucket);
  if (stat(fname, &st) < 0) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("stat");
    return SYS_ERROR;
  }
  return SUCCESS;
}

int dummy_delete_bucket(const char *bucket) {
  char fname[DUMMY_MAX_PATH];

  assert(bucket != NULL);

  if (strchr(bucket, '/')) {
    warning("Bucket contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s", dummy_path, bucket);
  if (rmdir(fname) < 0) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("rmdir");
    return SYS_ERROR;
  }
  return SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Objects

int dummy_list_object(const char *bucket, const char *prefix,
                      uint32_t max_count, struct store_list *list) {
  char fname[DUMMY_MAX_PATH];
  DIR *dir;
  struct dirent *ent;
  uint32_t count;

  assert(bucket != NULL);

  if (strchr(bucket, '/')) {
    warning("Bucket contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s", dummy_path, bucket);
  if (!(dir = opendir(fname))) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("opendir");
    return SYS_ERROR;
  }

  count = 0;
  while (count < max_count && (ent = readdir(dir))) {
    if (ent->d_type != DT_REG)
      continue;
    if (prefix && strncmp(ent->d_name, prefix, strlen(prefix)) < 0)
      continue;
    store_list_push(list, ent->d_name);
    count++;
  }

  closedir(dir);
  return SUCCESS;
}

int dummy_put_object(const char *bucket, const char *object,
                     const char *buf, uint32_t len) {
  char fname[DUMMY_MAX_PATH];
  FILE *file;
  size_t ret;

  assert(bucket != NULL && object != NULL);

  if (strchr(bucket, '/') || strchr(object, '/')) {
    warning("Bucket or object contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s/%s", dummy_path, bucket, object);
  if (!(file = fopen(fname, "w"))) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("fopen");
    return SYS_ERROR;
  }

  ret = fwrite(buf, len, 1, file);
  fclose(file);

  if (!ret) {
    stdwarning("fwrite");
    return SYS_ERROR;
  }
  return SUCCESS;
}

int dummy_get_object(const char *bucket, const char *object,
                     char **buf, uint32_t *len) {
  char fname[DUMMY_MAX_PATH], sbuf[1<<12],
       *data, *sdata;
  FILE *file;
  uint32_t data_len;
  size_t sbuf_len;

  assert(bucket != NULL && object != NULL);

  if (strchr(bucket, '/') || strchr(object, '/')) {
    warning("Bucket or object contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s/%s", dummy_path, bucket, object);
  if (!(file = fopen(fname, "r"))) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("fopen");
    return SYS_ERROR;
  }

  data = NULL;
  data_len = 0;
  while (1) {
    if (!(sbuf_len = fread(sbuf, 1, sizeof(sbuf), file)))
      break;
    if (!(sdata = realloc(data, data_len + sbuf_len)))
      stderror("realloc");
    memcpy(sdata + data_len, sbuf, sbuf_len);
    data = sdata;
    data_len += sbuf_len;
  }
  fclose(file);

  *buf = data;
  *len = data_len;
  return SUCCESS;
}

int dummy_exists_object(const char *bucket, const char *object) {
  char fname[DUMMY_MAX_PATH];
  struct stat st;

  assert(bucket != NULL && object != NULL);

  if (strchr(bucket, '/') || strchr(object, '/')) {
    warning("Bucket or object contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s/%s", dummy_path, bucket, object);
  if (stat(fname, &st) < 0) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("stat");
    return SYS_ERROR;
  }
  return SUCCESS;
}

int dummy_delete_object(const char *bucket, const char *object) {
  char fname[DUMMY_MAX_PATH];

  assert(bucket != NULL && object != NULL);

  if (strchr(bucket, '/') || strchr(object, '/')) {
    warning("Bucket or object contains invalid '/' character");
    return USER_ERROR;
  }

  snprintf(fname, sizeof(fname), "%s/%s/%s", dummy_path, bucket, object);
  if (unlink(fname) < 0) {
    if (errno == ENOENT)
      return NOT_FOUND;
    stdwarning("unlink");
    return SYS_ERROR;
  }
  return SUCCESS;
}
