/*
 * cloudfs: mt source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 *    A C-program for MT19937-64 (2004/9/29 version).
 *    Coded by Takuji Nishimura and Makoto Matsumoto.
 *
 *    This is a 64-bit version of Mersenne Twister pseudorandom number
 *    generator.
 *
 *    Before using, initialize the state by using init_genrand64(seed)
 *    or init_by_array64(init_key, key_length).
 *
 *    Copyright (C) 2004, Makoto Matsumoto and Takuji Nishimura,
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions
 *    are met:
 *
 *      1. Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 *      3. The names of its contributors may not be used to endorse or promote
 *         products derived from this software without specific prior written
 *         permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *    A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *    References:
 *    T. Nishimura, ``Tables of 64-bit Mersenne Twisters''
 *      ACM Transactions on Modeling and
 *      Computer Simulation 10. (2000) 348--357.
 *    M. Matsumoto and T. Nishimura,
 *      ``Mersenne Twister: a 623-dimensionally equidistributed
 *        uniform pseudorandom number generator''
 *      ACM Transactions on Modeling and
 *      Computer Simulation 8. (Jan. 1998) 3--30.
 *
 *    Any feedback is very welcome.
 *    http://www.math.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 *    email: m-mat @ math.sci.hiroshima-u.ac.jp (remove spaces)
 */


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include "mt.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       mt
// Description: 64-bit Mersenne Twister

////////////////////////////////////////////////////////////////////////////////
// Section:     Local macros

#define NN 312
#define MM 156
#define MATRIX_A 0xB5026F5AA96619E9ULL
#define UM 0xFFFFFFFF80000000ULL
#define LM 0x7FFFFFFFULL

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static uint64_t mt_seed[NN];

static int32_t mt_idx = NN + 1;

////////////////////////////////////////////////////////////////////////////////
// Section:     Seed random number generator

static uint32_t mix(uint32_t a, uint32_t b, uint32_t c) {
  a = a - b; a = a - c; a = a ^ (c >> 13);
  b = b - c; b = b - a; b = b ^ (a << 8);
  c = c - a; c = c - b; c = c ^ (b >> 13);
  a = a - b; a = a - c; a = a ^ (c >> 12);
  b = b - c; b = b - a; b = b ^ (a << 16);
  c = c - a; c = c - b; c = c ^ (b >> 5);
  a = a - b; a = a - c; a = a ^ (c >> 3);
  b = b - c; b = b - a; b = b ^ (a << 10);
  c = c - a; c = c - b; c = c ^ (b >> 15);
  return c;
}

void mt_init() {
  srand(mix(clock(), time(NULL), getpid()));
  mt_srand((((uint64_t) rand()) << 33) |
           (((uint64_t) rand()) << 2) |
           (rand() & 3));
}

void mt_srand(uint64_t seed) {
  mt_seed[0] = seed;
  for (mt_idx = 1; mt_idx < NN; mt_idx++)
    mt_seed[mt_idx] = (6364136223846793005ULL * (mt_seed[mt_idx-1] ^
                      (mt_seed[mt_idx-1] >> 62)) + mt_idx);
}

void mt_srand_arr(uint64_t init_key[], uint64_t key_length) {
  uint64_t i, j, k;

  mt_srand(19650218ULL);

  i = 1;
  j = 0;
  k = (NN > key_length ? NN : key_length);
  for (; k; k--) {
    mt_seed[i] = (mt_seed[i] ^ ((mt_seed[i-1] ^ (mt_seed[i-1] >> 62)) *
                 3935559000370003845ULL)) + init_key[j] + j;
    i++;
    j++;
    if (i >= NN) {
      mt_seed[0] = mt_seed[NN-1];
      i = 1;
    }
    if (j >= key_length) j = 0;
  }
  for (k = NN - 1; k; k--) {
    mt_seed[i] = (mt_seed[i] ^ ((mt_seed[i-1] ^ (mt_seed[i-1] >> 62)) *
                 2862933555777941757ULL)) - i;
    i++;
    if (i >= NN) {
      mt_seed[0] = mt_seed[NN-1];
      i = 1;
    }
  }

  mt_seed[0] = 1ULL << 63;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Generate random 64-bit number

uint64_t mt_rand() {
  int32_t i;
  uint64_t x;
  static uint64_t mag01[2] = {0ULL, MATRIX_A};

  if (mt_idx >= NN) {
    if (mt_idx == NN + 1)
      mt_srand(5489ULL);

    for (i = 0; i < NN - MM; i++) {
      x = (mt_seed[i] & UM) | (mt_seed[i+1] & LM);
      mt_seed[i] = mt_seed[i+MM] ^ (x >> 1) ^ mag01[(int)(x&1ULL)];
    }
    for (; i < NN - 1; i++) {
      x = (mt_seed[i] & UM) | (mt_seed[i+1] & LM);
      mt_seed[i] = mt_seed[i+(MM-NN)] ^ (x >> 1) ^ mag01[(int)(x&1ULL)];
    }
    x = (mt_seed[NN-1] & UM) | (mt_seed[0] & LM);
    mt_seed[NN-1] = mt_seed[MM-1] ^ (x >> 1) ^ mag01[(int)(x&1ULL)];

    mt_idx = 0;
  }

  x = mt_seed[mt_idx++];

  x ^= (x >> 29) & 0x5555555555555555ULL;
  x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
  x ^= (x << 37) & 0xFFF7EEE000000000ULL;
  x ^= (x >> 43);
  return x;
}
