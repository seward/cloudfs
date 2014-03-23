/*
 * cloudfs: misc header
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#ifndef min
#define min(a, b) ((a) > (b) ? (b) : (a))
#endif

#ifndef max
#define max(a, b) ((a) < (b) ? (b) : (a))
#endif

#ifndef sizearr
#define sizearr(a) (sizeof(a) / sizeof(*a))
#endif

#ifndef swap
#define swap(x, y) ({ typeof(x) f = y; y = x; x = f; })
#endif

////////////////////////////////////////////////////////////////////////////////
// Section:     Unit definitions

#define KILOBYTE  1024UL
#define MEGABYTE  (KILOBYTE * 1024UL)
#define GIGABYTE  (MEGABYTE * 1024UL)
#define TERABYTE  (GIGABYTE * 1024UL)
#define PETABYTE  (TERABYTE * 1024UL)

////////////////////////////////////////////////////////////////////////////////
// Section:     Typedefs

#ifndef __bool_true_false_are_defined
typedef enum bool { false = 0, true = 1 } bool;
#endif
