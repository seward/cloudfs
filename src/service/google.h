/*
 * cloudfs: google header
 *   By Benjamin Kittridge. Copyright (C) 2015, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "store.h"
#include "service/map.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Service table

extern const struct store_intr google_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     OAuth information

#define GOOGLE_ACCESS_TOKEN_SIZE (1 << 10)
#define GOOGLE_REFRESH_TOKEN_SIZE (1 << 10)

#define GOOGLE_API_REQUEST_RETRY  12

////////////////////////////////////////////////////////////////////////////////
// Section:     Load

void google_load();
FILE *google_open_token_file(const char *mode);
void google_request_refresh_token();
bool google_request_auth_token();
bool google_get_token(const char *key, bool refresh);

////////////////////////////////////////////////////////////////////////////////
// Section:     Buckets

int google_create_bucket(const char *bucket);
int google_exists_bucket(const char *bucket);
int google_delete_bucket(const char *bucket);

////////////////////////////////////////////////////////////////////////////////
// Section:     Objects

int google_list_object(const char *bucket, const char *prefix,
                       uint32_t max_count, struct store_list *list);
int google_put_object(const char *bucket, const char *object,
                      const char *buf, uint32_t len);
int google_get_object(const char *bucket, const char *object,
                      char **buf, uint32_t *len);
int google_exists_object(const char *bucket, const char *object);
int google_delete_object(const char *bucket, const char *object);

////////////////////////////////////////////////////////////////////////////////
// Section:     Google API

enum google_api_request_flags {
  GOOGLE_API_REQUEST_JSON = 1 << 0,
  GOOGLE_API_REQUEST_MD5 = 1 << 1,
};

struct google_api_request {
  const char *method, *url;
  uint32_t flags;

  const char *req_data, *req_ptr;
  uint32_t req_len, req_left;

  char *resp_data;
  uint32_t resp_len;
  long resp_code;
};

int google_api_call(const char *method, const char *url, uint32_t flags,
                    const char *req_data, uint32_t req_len, char **resp_data,
                    uint32_t *resp_len, map_t *json);
void google_api_perform(struct google_api_request *c);
size_t google_api_read_callback(void *ptr, size_t size, size_t nmemb,
                                void *stream);
size_t google_api_write_callback(void *ptr, size_t size, size_t nmemb,
                                 void *stream);
void google_api_request_free(struct google_api_request *c);

