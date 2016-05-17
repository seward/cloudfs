/*
 * cloudfs: google source
 *   By Benjamin Kittridge. Copyright (C) 2015, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <netdb.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/poll.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <curl/curl.h>
#include <wordexp.h>
#include "config.h"
#include "log.h"
#include "misc.h"
#include "service/google.h"
#include "service/base64.h"
#include "service/curl_util.h"
#include "service/json.h"
#include "service/map.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       google
// Description: Google Cloud Storage

////////////////////////////////////////////////////////////////////////////////
// Section:     Service table

const struct store_intr google_intr = {
  .load           = google_load,

  .create_bucket  = google_create_bucket,
  .exists_bucket  = google_exists_bucket,
  .delete_bucket  = google_delete_bucket,

  .list_object    = google_list_object,
  .put_object     = google_put_object,
  .get_object     = google_get_object,
  .exists_object  = google_exists_object,
  .delete_object  = google_delete_object,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static const char *google_client_id = NULL;

static const char *google_client_secret = NULL;

static const char *google_project_id = NULL;

static char google_access_token[GOOGLE_ACCESS_TOKEN_SIZE];

static sem_t google_access_token_sem;

static char google_refresh_token[GOOGLE_REFRESH_TOKEN_SIZE];

////////////////////////////////////////////////////////////////////////////////
// Section:     Load

void google_load() {
  const char *refresh_token;

  sem_init(&google_access_token_sem, 0, 1);
  if (!(google_client_id = config_get("google-client-id")))
    error("Must specify --google-client-id");
  if (!(google_client_secret = config_get("google-client-secret")))
    error("Must specify --google-client-secret");
  if (!(refresh_token = config_get("google-refresh-token")))
    error("Must specify --google-refresh-token");
  strncpy(google_refresh_token, refresh_token, GOOGLE_REFRESH_TOKEN_SIZE);
  if (!(google_project_id = config_get("google-project-id")))
    error("Must specify --google-project-id");

  curl_load();
  curl_load_openssl();

  if (!google_get_token())
    error("Failed to get google authorization token");
}

struct json_write_buf {
  char *buf;
  uint32_t size;
};

static size_t json_write_callback(void *ptr, size_t size, size_t nmemb,
                                  void *stream) {
  struct json_write_buf *write_buf;

  write_buf = (struct json_write_buf *)stream;

  size *= nmemb;
  if (!(write_buf->buf = realloc(write_buf->buf, write_buf->size + size + 1)))
    stderror("realloc");
  memcpy(write_buf->buf + write_buf->size, ptr, size);
  write_buf->buf[write_buf->size + size] = 0;
  write_buf->size += size;
  return size;
}

bool google_get_token() {
  char *data;
  CURL *curl;
  CURLcode ret;
  struct json_write_buf write_buf = {NULL, 0};

  data = NULL;
  asprintf(&data,
           "refresh_token=%s&client_id=%s&client_secret=%s"
           "&grant_type=refresh_token",
           google_refresh_token, google_client_id, google_client_secret);

  if (!(curl = curl_easy_init()))
    error("Unable to init curl");
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SHARE, curl_share_get());
  curl_easy_setopt(curl, CURLOPT_URL,
                   "https://accounts.google.com/o/oauth2/token");
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, json_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_buf);
  ret = curl_easy_perform(curl);
  if (ret != CURLE_OK) {
    error("Curl failed: %s", curl_easy_strerror(ret));
  } else {
    map_t json;
    const char *token;

    if (!(json = json_load(write_buf.buf)))
      error("Failed to load json auth response: %s", write_buf.buf);

    sem_wait(&google_access_token_sem);
    if (!(token = map_get_str(json, "access_token")))
      error("Google OAuth failed to provide access token");
    strncpy(google_access_token, token, GOOGLE_ACCESS_TOKEN_SIZE);
    if ((token = map_get_str(json, "refresh_token"))) {
      strncpy(google_refresh_token, token, GOOGLE_REFRESH_TOKEN_SIZE);
    }
    sem_post(&google_access_token_sem);
  }

  free(data);
  if (write_buf.buf)
    free(write_buf.buf);
  curl_easy_cleanup(curl);
  return ret == CURLE_OK;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Buckets

int google_create_bucket(const char *bucket) {
  char *url = NULL, *data;
  map_t input;
  int ret;

  asprintf(&url, "/storage/v1/b?project=%s", google_project_id);

  input = map_new("");
  map_set_str(input, "name", bucket);
  data = json_store(input);
  map_free(input);

  ret = google_api_call("POST", url, GOOGLE_API_REQUEST_JSON, data,
                        strlen(data), NULL, 0, NULL);
  free(url);
  free(data);
  return ret;
}

int google_exists_bucket(const char *bucket) {
  char *url = NULL;
  int ret;

  asprintf(&url, "/storage/v1/b/%s", bucket);
  ret = google_api_call("GET", url, 0, NULL, 0, NULL, 0, NULL);
  free(url);
  return ret;
}

int google_delete_bucket(const char *bucket) {
  char *url = NULL;
  int ret;

  asprintf(&url, "/storage/v1/b/%s", bucket);
  ret = google_api_call("DELETE", url, 0, NULL, 0, NULL, 0, NULL);
  free(url);
  return ret;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Objects

int google_list_object(const char *bucket, const char *prefix,
                       uint32_t max_count, struct store_list *list) {
  char *url = NULL;
  map_t json;
  int ret;

  asprintf(&url, "/storage/v1/b/%s/o?prefix=%s&maxResults=%u", bucket, prefix,
           max_count);
  ret = google_api_call("GET", url, 0, NULL, 0, NULL, 0, &json);
  if (ret == SUCCESS) {
    map_t item;

    map_foreach_under(item, json, "items") {
      const char *name;

      if ((name = map_get_str(item, "name"))) {
        store_list_push(list, name);
      }
    }
  }
  free(url);
  return ret;
}

int google_put_object(const char *bucket, const char *object,
                      const char *buf, uint32_t len) {
  char *url = NULL;
  int ret;

  asprintf(&url, "/upload/storage/v1/b/%s/o?name=%s", bucket, object);
  ret = google_api_call("POST", url, GOOGLE_API_REQUEST_MD5, buf, len, NULL,
                        0, NULL);
  free(url);
  return ret;
}

int google_get_object(const char *bucket, const char *object,
                      char **buf, uint32_t *len) {
  char *url = NULL;
  int ret;

  asprintf(&url, "/storage/v1/b/%s/o/%s?alt=media", bucket, object);
  ret = google_api_call("GET", url, 0, NULL, 0, buf, len, NULL);
  free(url);
  return ret;
}

int google_exists_object(const char *bucket, const char *object) {
  char *url = NULL;
  int ret;

  asprintf(&url, "/storage/v1/b/%s/o/%s", bucket, object);
  ret = google_api_call("GET", url, 0, NULL, 0, NULL, 0, NULL);
  free(url);
  return ret;
}

int google_delete_object(const char *bucket, const char *object) {
  char *url = NULL;
  int ret;

  asprintf(&url, "/storage/v1/b/%s/o/%s", bucket, object);
  ret = google_api_call("DELETE", url, 0, NULL, 0, NULL, 0, NULL);
  free(url);
  return ret;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Google API

int google_api_call(const char *method, const char *url, uint32_t flags,
                    const char *req_data, uint32_t req_len, char **resp_data,
                    uint32_t *resp_len, map_t *json) {
  struct google_api_request *c;
  int ret, retry;
  bool should_retry;

  ret = SYS_ERROR;

  for (retry = 0; retry < GOOGLE_API_REQUEST_RETRY; retry++) {
    if (!(c = calloc(sizeof(*c), 1)))
      stderror("calloc");
    c->method = method;
    c->url = url;
    c->flags = flags;
    c->req_data = req_data;
    c->req_ptr = req_data;
    c->req_len = req_len;
    c->req_left = req_len;
    c->resp_code = 500;
    google_api_perform(c);
    should_retry = false;
    switch (c->resp_code) {
      case 200:
      case 204:
        ret = SUCCESS;
        if (json) {
          google_api_write_callback("", 1, 1, c);
          if (!(*json = json_load(c->resp_data)))
            ret = SYS_ERROR;
        }
        if (resp_data) {
          *resp_data = c->resp_data;
          c->resp_data = NULL;
        }
        if (resp_len)
          *resp_len = c->resp_len;
        break;

      case 401:
        if (!google_get_token())
          warning("Failed to get google authorization token");

      case 500:
      case 503:
        should_retry = true;
        break;

      case 404:
        ret = NOT_FOUND;
        break;
    }
    google_api_request_free(c);
    if (should_retry) {
      if (retry >= 2)
        warning("Failure while contacting Google Cloud Storage, retrying...");
      sleep(retry * 5);
      continue;
    }
    break;
  }
  return ret;
}

void google_api_perform(struct google_api_request *c) {
  CURL *curl;
  CURLcode ret;
  struct curl_slist *header;
  char dig[MD5_DIGEST_LENGTH], *md5, *host;

  if (!(curl = curl_easy_init()))
    error("Unable to init curl");
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SHARE, curl_share_get());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, c->method);
  if (!strcasecmp(c->method, "HEAD"))
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
  if (asprintf(&host, "https://www.googleapis.com%s", c->url) < 0)
    stderror("asprintf");
  curl_easy_setopt(curl, CURLOPT_URL, host);
  free(host);

#define set_header(name, value, x...) ({ \
      char *hdr; \
      if (asprintf(&hdr, "%s: " value, name, ##x) < 0) \
        stderror("asprintf"); \
      header = curl_slist_append(header, hdr); \
      free(hdr); })

  header = NULL;
  sem_wait(&google_access_token_sem);
  set_header("Authorization", "OAuth %s", google_access_token);
  sem_post(&google_access_token_sem);
  if ((c->flags & GOOGLE_API_REQUEST_JSON))
    set_header("Content-Type", "application/json");
  if ((c->flags & GOOGLE_API_REQUEST_MD5)) {
    MD5((uint8_t *)c->req_data, c->req_len, (uint8_t *)dig);
    base64_encode(dig, sizeof(dig), &md5);
    set_header("Content-MD5", "%s", md5);
    free(md5);
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);

  if (c->req_len) {
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) c->req_len);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, google_api_read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, c);
  }

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, google_api_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, c);

  if ((ret = curl_easy_perform(curl)) != CURLE_OK) {
    warning("Curl failed: %s", curl_easy_strerror(ret));
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &c->resp_code);
  }

  curl_slist_free_all(header);
  curl_easy_cleanup(curl);
}

size_t google_api_read_callback(void *ptr, size_t size, size_t nmemb,
                                void *stream) {
  struct google_api_request *c;
  size_t len;

  c = (struct google_api_request*) stream;

  size *= nmemb;
  len = min(size, c->req_left);

  memcpy(ptr, c->req_ptr, len);
  c->req_ptr  += len;
  c->req_left -= len;
  return len;
}

size_t google_api_write_callback(void *ptr, size_t size, size_t nmemb,
                                 void *stream) {
  struct google_api_request *c;

  c = (struct google_api_request*) stream;

  size *= nmemb;

  if (!(c->resp_data = realloc(c->resp_data, c->resp_len + size)))
    stderror("realloc");
  memcpy(c->resp_data + c->resp_len, ptr, size);
  c->resp_len += size;
  return size;
}

void google_api_request_free(struct google_api_request *c) {
  if (c->resp_data)
    free(c->resp_data);
  free(c);
}
