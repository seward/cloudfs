/*
 * cloudfs: curl_util source
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

////////////////////////////////////////////////////////////////////////////////
// Class:       curl_util
// Description: Utilities for curl

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static CURLSH *curl_share = NULL;

static sem_t curl_share_sem;

static sem_t *curl_openssl_sem = NULL;

////////////////////////////////////////////////////////////////////////////////
// Section:     Curl Init

static void curl_share_lock(CURL *handle, curl_lock_data data,
                            curl_lock_access access, void *useptr) {
  sem_wait(&curl_share_sem);
}

static void curl_share_unlock(CURL *handle, curl_lock_data data, void *useptr) {
  sem_post(&curl_share_sem);
}

void curl_load() {
  curl_global_init(CURL_GLOBAL_ALL);

  sem_init(&curl_share_sem, 0, 1);
  curl_share = curl_share_init();
  if (curl_share_setopt(curl_share, CURLSHOPT_LOCKFUNC,
                        curl_share_lock))
    error("curl_share_setopt failed");
  if (curl_share_setopt(curl_share, CURLSHOPT_UNLOCKFUNC,
                        curl_share_unlock))
    error("curl_share_setopt failed");
  if (curl_share_setopt(curl_share, CURLSHOPT_SHARE,
                        CURL_LOCK_DATA_DNS))
    error("curl_share_setopt failed");
}

void curl_openssl_locking_function(int mode, int n, const char *file,
                                   int line) {
  if (mode & CRYPTO_LOCK)
    sem_wait(&curl_openssl_sem[n]);
  else
    sem_post(&curl_openssl_sem[n]);
}

unsigned long openssl_id_function() {
  return pthread_self();
}

void curl_load_openssl() {
  uint32_t i, num_locks;

  num_locks = CRYPTO_num_locks();
  if (!(curl_openssl_sem = calloc(num_locks, sizeof(*curl_openssl_sem))))
    stderror("calloc");
  for (i = 0; i < num_locks; i++)
    sem_init(&curl_openssl_sem[i], 0, 1);
  CRYPTO_set_id_callback(openssl_id_function);
  CRYPTO_set_locking_callback(curl_openssl_locking_function);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Getters

CURLSH *curl_share_get() {
  return curl_share;
}

