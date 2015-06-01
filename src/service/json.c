/*
 * cloudfs: json source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "service/map.h"
#include "service/json.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       json
// Description: Parses json file into map

////////////////////////////////////////////////////////////////////////////////
// Section:     Serialization

map_t json_load(char *data) {
  char *ptr, *ptr2, *end;
  struct {
    char *name;
    map_t map;
    bool group, val;
  } tree[D_MAP_MAX_TREE];
  map_t p, np;
  uint32_t cur;
  bool f, success;
  int32_t n, sc_chr;

  success = false;
  cur = 0;
  p = NULL;
  ptr = data;
  end = data + strlen(data);

  memset(tree, 0, sizeof(tree));

  while(1) {
    if (!*ptr)
      break;
    for (; isspace(*ptr); ptr++);
    if (!*ptr)
      break;

    switch (*ptr) {
      case '{':
        if (!p) {
          if (!(p = map_new("")))
            goto error;
          tree[cur].map = p;
        }
        else if (tree[cur].val || tree[cur].group) {
          if (++cur >= D_MAP_MAX_TREE)
            goto error;
          if (!(tree[cur].map = map_set(tree[cur-1].map,
              tree[cur-1].name)))
            goto error;
        }
        else
          goto error;
        tree[cur].name = NULL;
        tree[cur].val = false;
        tree[cur].group = false;
        break;

      case '[':
        if (!p)
          goto error;
        if (++cur >= D_MAP_MAX_TREE)
          goto error;
        tree[cur].map = tree[cur-1].map;
        tree[cur].name = tree[cur-1].name;
        tree[cur].val = true;
        tree[cur].group = true;
        break;

      case ':':
        tree[cur].val = true;
        break;

      case ',':
        if (tree[cur].group)
          break;
        if (tree[cur].name)
          free(tree[cur].name);
        tree[cur].name = NULL;
        tree[cur].val = false;
        break;

      case '"':
      case '\'':
        sc_chr = *ptr;
        ptr2 = ++ptr;
        for (n = 0, f = false; !f && ptr < end; ptr++) {
          switch (*ptr) {
            case '\\':
              n = !n;
              break;
            default:
              if (!*ptr || (*ptr == sc_chr && !n))
                f = true;
              n = 0;
              break;
          }
        }

        ptr--;
        if (!(ptr2 = json_decode(ptr2, ptr - ptr2)))
          goto error;

        if (tree[cur].val) {
          if (!map_set_str(tree[cur].map, tree[cur].name, ptr2))
            goto error;
          free(ptr2);
        }
        else if (!tree[cur].group) {
          if (tree[cur].name)
            free(tree[cur].name);
          tree[cur].name = ptr2;
        }
        break;

      case '}':
      case ']':
        if (!tree[cur].group) {
          if (tree[cur].name)
            free(tree[cur].name);
          tree[cur].name = NULL;
        }

        if (cur)
          cur--;
        break;
        
      default:
        for (ptr2 = ptr; ptr < end; ptr++) {
          if (!isalnum(*ptr) && *ptr != '.' && *ptr != '-')
            break;
        }
        if (ptr == ptr2)
          goto error;

        if (tree[cur].val && tree[cur].name) {
          if (!(np = map_set_strn(tree[cur].map, tree[cur].name,
              ptr2, ptr - ptr2)))
            goto error;
          np->type = D_MAP_TYPE_UNESCAPED;
        }
        else if (!tree[cur].group) {
          if (tree[cur].name)
            free(tree[cur].name);
          tree[cur].name = strndup(ptr2, ptr - ptr2);
          if (!tree[cur].name)
            stderror("strndup");
        }
        ptr--;
        break;
    }
    ptr++;
  }

  success = true;

error:
  while (1) {
    if (tree[cur].name)
      free(tree[cur].name);
    tree[cur].name = NULL;

    if (cur)
      cur--;
    else
      break;
  }

  if (success)
    return p;

  if (p)
    map_free(p);
  return NULL;
}

char *json_store(map_t p) {
  struct {
    map_t map, first;
    bool group;
  } tree[D_MAP_MAX_TREE];
  map_t fs;
  char *buf, *name, *value, *comma;
  uint32_t cur, size, quote;
  bool group, after, match;
  
  if (!p->child) {
    return strdup("{}");
  }

  buf = NULL;
  name = NULL;
  value = NULL;
  size = 0;
  cur = 0;
  comma = "";
  
  tree[cur].map = p;
  tree[cur].first = p;
  tree[cur].group = false;

  while(1) {
    p = tree[cur].map;
    group = tree[cur].group;
    if (!p) {
      if (!cur)
        break;
      cur--;

      if (!(buf = realloc(buf, size + 2)))
        stderror("realloc");
      if (group)
        size += sprintf(buf + size, "]");
      else
        size += sprintf(buf + size, "}");
      comma = ",";

      p = tree[cur].map;
      group = tree[cur].group;

      if (group) {
        for (p = p->next; p; p = p->next) {
          if (!strcmp(tree[cur].first->name, p->name))
            break;
        }
        tree[cur].map = p;
      } else {
        tree[cur].map = p->next;
      }
      continue;
    }

    if (!p->name)
      name = NULL;
    else if (!(name = json_encode(p->name, strlen(p->name))))
      goto error;

    if (!p->value)
      value = NULL;
    else if (!(value = json_encode(p->value, strlen(p->value))))
      goto error;
    
    quote = !(p->type == D_MAP_TYPE_UNESCAPED);

    match = false;
    if (!group) {
      after = false;
      for (fs = tree[cur].first; fs; fs = fs->next) {
        if (fs == p)
          after = true;
        else if (p->name && !strcmp(fs->name, p->name)) {
          match = true;
          break;
        }
      }

      if (match) {
        if (!after) {
          tree[cur].map = p->next;
          goto next;
        }

        if (cur + 1 >= D_MAP_MAX_TREE)
          goto error;
        cur++;
        tree[cur].map = p;
        tree[cur].first = p;
        tree[cur].group = true;
      }
    }

    if (p->child) {
      if (!(buf = realloc(buf, size + (name ? strlen(name) : 0) + 7)))
        stderror("realloc");
      if (!cur || group) {
        size += sprintf(buf + size, "%s%s{", comma, (match ? "[" : ""));
      } else {
        size += sprintf(buf + size, "%s\"%s\":%s{", comma, (name ? name : ""),
                        (match ? "[" : ""));
      }
      comma = "";

      if (cur + 1 >= D_MAP_MAX_TREE)
        goto error;
      cur++;
      tree[cur].map = p->child;
      tree[cur].first = p->child;
      tree[cur].group = false;
    }
    else {
      if (name) {
        if (!(buf = realloc(buf, size + strlen(name) +
                                 (value ? strlen(value) : 0) + 8)))
          stderror("realloc");
        if (group) {
          size += sprintf(buf + size, "%s%s%s%s", comma,
              (quote ? "\"" : ""), (value ? value : ""),
              (quote ? "\"" : ""));
        } else {
          size += sprintf(buf + size, "%s\"%s\":%s%s%s%s", comma,
              name, (match ? "[" : ""),
              (quote ? "\"" : ""), (value ? value : ""),
              (quote ? "\"" : ""));
        }
        comma = ",";
      }

      if (group) {
        for (p = p->next; p; p = p->next) {
          if (!strcmp(tree[cur].first->name, p->name))
            break;
        }
        tree[cur].map = p;
      } else {
        tree[cur].map = p->next;
      }
    }

next:
    if (name)
      free(name);
    name = NULL;

    if (value)
      free(value);
    value = NULL;
  }
  return buf;

error:
  if (name)
    free(name);
  if (value)
    free(value);
  if (buf)
    free(buf);
  return NULL;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Encoding / Decoding special characters

char *json_encode(char *str, uint32_t len) {
  static char *set[0xff] = {
    ['\\'] = "\\\\",
    ['"']  = "\\\"",
  };
  char *ptr, *nptr, *nstr, *f;
  uint32_t rlen;

  for (rlen = 0, ptr = str; ptr - str < len; ptr++) {
    f = set[(uint8_t)*ptr];
    if (f)
      rlen += strlen(f);
    else if (!isprint(*ptr))
      rlen += 4;
    else
      rlen++;
  }

  if (!(nstr = calloc(rlen + 1, 1)))
    stderror("calloc");
  for (ptr = str, nptr = nstr; ptr - str < len; ptr++) {
    f = set[(uint8_t)*ptr];
    if (f) {
      strcpy(nptr, f);
      nptr += strlen(f);
    } else if (!isprint(*ptr)) {
      sprintf(nptr, "\\x%02X", (uint8_t)*ptr);
      nptr += 4;
    } else {
      *nptr++ = *ptr;
    }
  }
  *nptr = 0;
  return nstr;
}

char *json_decode(char *str, uint32_t len) {
  static struct {
    char *ent, ctr;
  } set[] = {
    { "\\\\", '\\' },
    { "\\\"",  '"' },
    {  "\\'", '\'' },
  };
  uint32_t i, num;
  char *ptr, *nptr, *nstr;
  bool f;

  if (!(nstr = calloc(len + 1, 1)))
    stderror("calloc");
  for (ptr = str, nptr = nstr; ptr - str < len; ptr++) {
    if (*ptr == '\\') {
      for (f = false, i = 0; i < sizeof(set) / sizeof(*set); i++) {
        if (!strncmp(ptr, set[i].ent, strlen(set[i].ent))) {
          *nptr++ = set[i].ctr;
          ptr += strlen(set[i].ent) - 1;
          f = true;
          break;
        }
      }
      if (!f && ptr[1] == 'x') {
        num = strtoul(ptr + 2, NULL, 16);
        if (num > 0xff) {
          *nptr++ = num & 0xff;
          *nptr++ = (num >> 8) & 0xff;
        } else {
          *nptr++ = num;
        }
        ptr++;
      }
      ptr++;
    }
    else
      *nptr++ = *ptr;
  }
  *nptr = 0;
  return nstr;
}
