/*
 * cloudfs: mt header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include <stdint.h>

////////////////////////////////////////////////////////////////////////////////
// Section:     Public functions

void mt_init();
void mt_srand(uint64_t seed);
void mt_srand_arr(uint64_t init_key[], uint64_t key_length);

uint64_t mt_rand();
