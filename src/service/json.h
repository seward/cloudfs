/*
 * cloudfs: json header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>
#include "service/map.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

map_t json_load(char *data);
char *json_store(map_t p);

char *json_encode(char *str, uint32_t len);
char *json_decode(char *str, uint32_t len);
