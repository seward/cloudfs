/*
 * cloudfs: misc source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include "config.h"
#include "misc.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       misc
// Description: Misc

////////////////////////////////////////////////////////////////////////////////
// Section:     Curl-safe fork

void misc_maybe_fork() {
  pid_t pid;
  if (config_get("nofork"))
    return;

  curl_global_cleanup();

  pid = fork();
  if (pid > 0)
    exit(0);
  else if (pid == 0)
    return;
  else
    stderror("fork");

  curl_global_init(CURL_GLOBAL_ALL);
}

