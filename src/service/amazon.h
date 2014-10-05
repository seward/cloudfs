/*
 * cloudfs: amazon header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include <stdbool.h>
#include "store.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define AMAZON_REQUEST_RETRY  12

////////////////////////////////////////////////////////////////////////////////
// Section:     Request methods

enum amazon_request_method {
  AMAZON_REQUEST_GET,
  AMAZON_REQUEST_PUT,
  AMAZON_REQUEST_DELETE,
  AMAZON_REQUEST_HEAD
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Amazon request context structure

struct amazon_request {
  enum amazon_request_method method;
  const char *bucket;
  char *location, *object;

  const char *req_data, *req_ptr;
  uint32_t req_len, req_left;

  char *resp_data;
  uint32_t resp_len;
  long resp_code;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Service table

extern const struct store_intr amazon_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     Configuration

extern const char *amazon_key, *amazon_secret, *amazon_location;

////////////////////////////////////////////////////////////////////////////////
// Section:     Load

void amazon_load();
void amazon_load_curl();

////////////////////////////////////////////////////////////////////////////////
// Section:     Buckets

int amazon_list_bucket(const char *prefix, uint32_t max_count,
                       struct store_list *list);
int amazon_create_bucket(const char *bucket);
int amazon_exists_bucket(const char *bucket);
int amazon_delete_bucket(const char *bucket);

////////////////////////////////////////////////////////////////////////////////
// Section:     Objects

int amazon_list_object(const char *bucket, const char *prefix,
                       uint32_t max_count, struct store_list *list);
int amazon_put_object(const char *bucket, const char *object,
                      const char *buf, uint32_t len);
int amazon_get_object(const char *bucket, const char *object,
                      char **buf, uint32_t *len);
int amazon_exists_object(const char *bucket, const char *object);
int amazon_delete_object(const char *bucket, const char *object);

////////////////////////////////////////////////////////////////////////////////
// Section:     Amazon request

int amazon_request_call(enum amazon_request_method method,
                        const char *bucket, const char *object,
                        const char *data, uint32_t data_len,
                        char **out_buf, uint32_t *out_len);

////////////////////////////////////////////////////////////////////////////////
// Section:     Request initialization

struct amazon_request *amazon_request_new(enum amazon_request_method method,
                                          const char *bucket,
                                          const char *object);
void amazon_request_set_req(struct amazon_request *c, const char *data,
                            uint32_t data_len);

////////////////////////////////////////////////////////////////////////////////
// Section:     Generate and write request

void amazon_request_perform(struct amazon_request *c);
char *amazon_request_access(struct amazon_request *c, const char *date,
                            const char *md5);

////////////////////////////////////////////////////////////////////////////////
// Section:     Curl callbacks

size_t amazon_request_read_callback(void *ptr, size_t size, size_t nmemb,
                                    void *stream);
size_t amazon_request_write_callback(void *ptr, size_t size, size_t nmemb,
                                     void *stream);

////////////////////////////////////////////////////////////////////////////////
// Section:     Free request

void amazon_request_free(struct amazon_request *c);
