/*
 * cloudfs: trxlog source
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "misc.h"
#include "log.h"
#include "trxlog.h"

////////////////////////////////////////////////////////////////////////////////
// Module:      trxlog
// Description: Manages transaction log

////////////////////////////////////////////////////////////////////////////////
// Section:     Transaction log

void trxlog_add(struct trxlog *t, uint32_t from, uint32_t len) {
	struct trxlog_range *r1, *r2;
	uint32_t to, i, j, s;

	to = from + len;

	for (i = 0; i < t->size; i++) {
		r1 = &t->range[i];
		if ((from >= r1->from && from <= r1->to) ||
		    (to   >= r1->from && to   <= r1->to)) {
			r1->from = min(r1->from, from);
			r1->to   = max(r1->to,   to);
			for (s = 0, j = i + 1; j < t->size; j++) {
				r2 = &t->range[j];
				if (!((r2->from >= r1->from && r2->from <= r1->to) ||
				      (r2->to   >= r1->from && r2->to   <= r1->to)))
					break;
				r1->from = min(r1->from, r2->from);
				r1->to   = max(r1->to,   r2->to);
				s++;
			}
			if (s) {
				for (j = i + s + 1; j < t->size; j++) {
					r1 = &t->range[j - s];
					r2 = &t->range[j];
					r1->from = r2->from;
					r1->to   = r2->to;
				}
				t->size -= s;
			}
			return;
		}
		if (r1->from > from)
			break;
	}

	if (t->size + 1 > t->alloc_size) {
		t->alloc_size += TRXLOG_STEP;
		if (!(t->range = realloc(t->range, sizeof(*t->range) * t->alloc_size)))
			stderror("realloc");
	}

	for (j = t->size - 1; t->size && j >= i; j--) {
		r1 = &t->range[j + 1];
		r2 = &t->range[j];
		r1->from = r2->from;
		r1->to   = r2->to;
		if (!j)
			break;
	}

	r1 = &t->range[i];
	r1->from = from;
	r1->to   = to;
	t->size++;
}

bool trxlog_match(struct trxlog *t, uint32_t from, uint32_t len) {
	struct trxlog_range *r;
	uint32_t to, i;

	to = from + len;

	for (i = 0; i < t->size; i++) {
		r = &t->range[i];
		if (from >= r->from && to <= r->to)
			return true;
		if (r->from > from)
			break;
	}
	return false;
}

void trxlog_list(struct trxlog *t, uint32_t from, uint32_t to, uint32_t *len, bool *mark) {
	struct trxlog_range *r;
	uint32_t i;

	for (i = 0; i < t->size; i++) {
		r = &t->range[i];
		if (r->from <= from && r->to > from) {
			*len  = min(to, r->to) - from;
			*mark = true;
			return;
		}
		else if (r->from > from) {
			*len  = min(to, r->from) - from;
			*mark = false;
			return;
		}
	}

	*len  = to - from;
	*mark = false;
}

void trxlog_copy(struct trxlog *t, struct trxlog *t2) {
	t->size = t2->size;
	t->alloc_size = t->size;
	if (t->range)
		free(t->range);
	if (!(t->range = malloc(sizeof(*t->range) * t->size)))
		stderror("malloc");
	memcpy(t->range, t2->range, sizeof(*t->range) * t->size);
}

void trxlog_free(struct trxlog *t) {
	t->size = 0;
	t->alloc_size = 0;
	if (t->range)
		free(t->range);
	t->range = NULL;
}
