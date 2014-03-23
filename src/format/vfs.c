/*
 * cloudfs: vfs source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#ifdef HAVE_FUSE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "config.h"
#include "log.h"
#include "object.h"
#include "store.h"
#include "misc.h"
#include "mt.h"
#include "format/vfs.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       vfs
// Description: FUSE vfs storage format

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static struct vfs_fd *vfs_fd_list = NULL;

static uint64_t vfs_fsid = 0;

////////////////////////////////////////////////////////////////////////////////
// Section:     Format table

const struct volume_intr vfs_intr = {
  .mount    = vfs_mount,
  .unmount  = vfs_unmount,
  .fsck     = vfs_fsck,
};

static struct fuse_operations vfs_oper = {
  .getattr       = vfs_fuse_getattr,
  .fgetattr      = vfs_fuse_fgetattr,
  .access        = vfs_fuse_access,
  .readlink      = vfs_fuse_readlink,
  .readdir       = vfs_fuse_readdir,
  .mknod         = vfs_fuse_mknod,
  .mkdir         = vfs_fuse_mkdir,
  .create        = vfs_fuse_create,
  .open          = vfs_fuse_open,
  .symlink       = vfs_fuse_symlink,
  .unlink        = vfs_fuse_unlink,
  .rmdir         = vfs_fuse_rmdir,
  .rename        = vfs_fuse_rename,
  .link          = vfs_fuse_link,
  .chmod         = vfs_fuse_chmod,
  .chown         = vfs_fuse_chown,
  .truncate      = vfs_fuse_truncate,
  .ftruncate     = vfs_fuse_ftruncate,
  .utime         = vfs_fuse_utime,
  .read          = vfs_fuse_read,
  .write         = vfs_fuse_write,
  .flush         = vfs_fuse_flush,
  .release       = vfs_fuse_release,
  .fsync         = vfs_fuse_fsync,
  .statfs        = vfs_fuse_statfs,

  .flag_nullpath_ok  = 0,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Helper function

static uint64_t unique_id() {
  return (((uint64_t) (time(NULL) & 0xffffffff)) << 32) |
         (mt_rand() & 0xffffffff);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Call vfs

void vfs_mount(const struct volume_metadata *md, const char *path) {
  const char *argv[] = {
      "cloudfs", path,
      "-f", "-s",
      NULL };

  notice("Volume mounting on %s", path);

  if (!config_get("nofork")) {
    if (fork())
      exit(0);
  }

  object_load();

  vfs_fsid = unique_id();

  if (fuse_main(sizearr(argv) - 1, (char**) argv, &vfs_oper, NULL) != 0)
    warning("FUSE failed");

  notice("Volume disconnecting");

  vfs_fd_clear();
  object_unload();
}

void vfs_unmount(const struct volume_metadata *md, const char *path) {
  pid_t pid;

  if (!(pid = fork())) {
    execlp("fusermount", "fusermount", "-u", path, NULL);
    exit(0);
  }
  waitpid(pid, NULL, 0);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Check filesystem

void vfs_fsck(const struct volume_metadata *md) {
  object_load();

  vfs_fsck_dir(0);

  object_unload();

  notice("Filesystem is clean");
}

void vfs_fsck_dir(uint64_t inode) {
  struct vfs_inode **list, **lptr;

  if (!(list = vfs_dir_read(inode, NULL)))
    return;

  for (lptr = list; *lptr; lptr++) {
    struct vfs_inode *node = *lptr;

    if (S_ISDIR(node->data.mode)) {
      vfs_fsck_dir(node->data.ino);
    } else {
      // TODO: Write me
    }
  }

  vfs_dir_read_free(list);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Path parsing

char **vfs_path_split(char *str) {
  char **dst, *ptr, *path;
  uint32_t i;

  path = str;
  ptr = path;

  if (!(dst = malloc(sizeof(*dst))))
    stderror("malloc");
  dst[0] = NULL;
  i = 0;

  while (1) {
    if (*ptr == VFS_PATH_SEPERATOR || !*ptr) {
      if (*ptr)
        *ptr++ = 0;

      if (*path) {
        if (!(dst = realloc(dst, (i + 2) * sizeof(*dst))))
          stderror("realloc");
        dst[i] = path;
        dst[i + 1] = NULL;
        i++;
      }

      if (!*ptr)
        break;
      path = ptr;
    } else {
      ptr++;
    }
  }
  return dst;
}

void vfs_path_split_free(char **dst) {
  free(dst);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Directory operations

struct vfs_inode **vfs_dir_read(uint64_t inode,
                                struct vfs_inode_ptr *empty_ptr) {
  uint32_t i;
  struct vfs_inode_ptr ptr;
  struct vfs_inode **node_list, *node;
  bool found_empty;

  if (!(node_list = malloc(sizeof(*node_list))))
    stderror("malloc");
  node_list[0] = NULL;
  node = NULL;
  i = 0;

  found_empty = false;
  ptr.object.index = inode;
  ptr.object.chunk = 0;
  ptr.offt = 0;
  while (1) {
    if (!(node = calloc(sizeof(*node), 1)))
      stderror("calloc");

    if (!vfs_dir_read_pass(&ptr, &node->ptr, &node->data, sizeof(node->data))) {
      free(node);
      break;
    }
    if (!(node->data.flag & VFS_INODE_FLAG_VALID)) {
      if (empty_ptr && !found_empty) {
        memcpy(empty_ptr, &node->ptr, sizeof(*empty_ptr));
        found_empty = true;
      }
      free(node);
      continue;
    }

    if (!(node_list = realloc(node_list, (i + 2) * sizeof(*node_list))))
      stderror("realloc");
    node_list[i] = node;
    node_list[i + 1] = NULL;
    node = NULL;
    i++;
  }

  if (empty_ptr && !found_empty)
    vfs_dir_read_pass(&ptr, empty_ptr, NULL, sizeof(node->data));
  return node_list;
}

bool vfs_dir_read_pass(struct vfs_inode_ptr *ptr,
                       struct vfs_inode_ptr *save_ptr,
                       void *data, uint32_t len) {
  uint32_t rlen;
  int ret;

  if (ptr->offt + len > OBJECT_MAX_SIZE) {
    ptr->object.chunk++;
    ptr->offt = 0;
  }
  memcpy(save_ptr, ptr, sizeof(*ptr));

  if (!data)
    return true;

  if ((ret = object_read(ptr->object, ptr->offt, data,
                         len, &rlen)) != SUCCESS) {
    if (ret != NOT_FOUND)
      warning("Read error on inode %016" PRIx64, ptr->object.index);
    return false;
  }
  if (rlen < len)
    return false;

  ptr->offt += rlen;
  return true;
}

void vfs_dir_read_free(struct vfs_inode **list) {
  struct vfs_inode **lptr;

  for (lptr = list; *lptr; lptr++) {
    struct vfs_inode *node = *lptr;

    vfs_node_free(node);
  }
  free(list);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Node lookup

int vfs_node_lookup(const char *path, struct vfs_inode **out_node,
                    bool new_file) {
  struct vfs_inode *res_node;
  struct vfs_inode_ptr empty_ptr, *pend;
  char *mpath, **path_list, **pptr;
  uint64_t parent_inode;
  bool found;
  int ret;

  if (!(mpath = strdup(path)))
    stderror("strdup");
  if (!(path_list = vfs_path_split(mpath)))
    error("Error splitting path");
  if (!(res_node = calloc(sizeof(*res_node), 1)))
    stderror("calloc");

  pend = (new_file ? &empty_ptr : NULL);

  ret = 0;
  parent_inode = 0;
  if (!path_list[0]) {
    if (new_file) {
      ret = -EEXIST;
    } else {
      strcpy(res_node->data.name, "/");
      res_node->data.mode = S_IFDIR | 0755;
      res_node->data.nlink = 2;
      res_node->data.ctime = res_node->data.mtime =
                             res_node->data.atime = time(NULL);
      res_node->is_root = true;
    }
  } else {
    for (pptr = path_list; *pptr; pptr++) {
      struct vfs_inode **list, **lptr;
      bool last_file = (pptr[1] ? false : true);

      if (!(list = vfs_dir_read(parent_inode, pend))) {
        warning("File system missing data at inode %016" PRIx64,
                parent_inode);
        ret = -EFAULT;
        break;
      }

      found = false;
      for (lptr = list; *lptr; lptr++) {
        struct vfs_inode *found_node = *lptr;

        if (!strcmp(found_node->data.name, *pptr)) {
          if (last_file)
            memcpy(res_node, found_node, sizeof(*res_node));
          parent_inode = found_node->data.ino;
          if (last_file || S_ISDIR(found_node->data.mode))
            found = true;
          else
            ret = -ENOTDIR;
          break;
        }
      }

      vfs_dir_read_free(list);

      if (new_file && last_file) {
        if (found) {
          ret = -EEXIST;
        } else if (strlen(*pptr) > VFS_PATH_MAX - 1) {
          ret = -ENAMETOOLONG;
        } else {
          memcpy(&res_node->ptr, &empty_ptr, sizeof(res_node->ptr));
          strcpy(res_node->data.name, *pptr);
          res_node->data.ino = unique_id();
          res_node->data.flag |= VFS_INODE_FLAG_VALID;
          res_node->data.ctime = res_node->data.mtime =
                                 res_node->data.atime = time(NULL);
          res_node->new_file = true;
        }
        break;
      }
      if (!found) {
        if (!ret)
          ret = -ENOENT;
        break;
      }
    }
  }

  vfs_path_split_free(path_list);
  free(mpath);

  if (!ret && out_node) {
    res_node->data.atime = time(NULL);
    *out_node = res_node;
  } else {
    vfs_node_free(res_node);
  }
  return ret;
}

int vfs_node_rehash(struct vfs_inode *node) {
  struct vfs_inode_data node_data;
  uint32_t rlen;

  if (object_read(node->ptr.object, node->ptr.offt, (char*) &node_data,
                  sizeof(node_data), &rlen) != SUCCESS ||
      rlen < sizeof(node_data)) {
    warning("Read error on inode %016" PRIx64, node->ptr.object.index);
    return -EFAULT;
  }
  if (node->data.ino == node_data.ino &&
      (node_data.flag & VFS_INODE_FLAG_VALID))
    memcpy(&node->data, &node_data, sizeof(node_data));
  return 0;
}

int vfs_node_commit(struct vfs_inode *node) {
  struct vfs_inode_data node_data;
  uint32_t rlen;

  if (node->is_root)
    return 0;

  if (!node->new_file) {
    if (object_read(node->ptr.object, node->ptr.offt, (char*) &node_data,
                    sizeof(node_data), &rlen) != SUCCESS ||
        rlen < sizeof(node_data)) {
      warning("Read error on inode %016" PRIx64, node->ptr.object.index);
      return -EFAULT;
    }
    if (node->data.ino != node_data.ino ||
        !(node_data.flag & VFS_INODE_FLAG_VALID))
      return 0;
  }

  if (object_write(node->ptr.object, node->ptr.offt, (const char*) &node->data,
                   sizeof(node->data)) != SUCCESS) {
    warning("Write error on inode %016" PRIx64, node->ptr.object.index);
    return -EFAULT;
  }
  return 0;
}

int vfs_node_commit_and_free(struct vfs_inode *node) {
  int ret;

  ret = vfs_node_commit(node);
  vfs_node_free(node);
  return ret;
}

int vfs_node_delete(struct vfs_inode *node) {
  struct volume_object object;
  struct vfs_inode_ptr last_ptr;
  uint64_t max_chunk;

  object.index = node->data.ino;
  object.chunk = 0;
  if (S_ISDIR(node->data.mode)) {
    struct vfs_inode **list;

    if (!(list = vfs_dir_read(node->data.ino, &last_ptr))) {
      warning("File system missing data at inode %016" PRIx64,
              node->data.ino);
      return -EFAULT;
    }
    vfs_dir_read_free(list);

    max_chunk = last_ptr.object.chunk;
  } else {
    max_chunk = node->data.last_block >> OBJECT_MAX_SIZE_LOG2;
  }

  while (object.chunk <= max_chunk) {
    if (object_delete(object) != SUCCESS) {
      warning("Delete error on inode %016" PRIx64, object.index);
      break;
    }
    object.chunk++;
  }

  node->data.flag &= ~VFS_INODE_FLAG_VALID;
  return 0;
}

void vfs_node_free(struct vfs_inode *node) {
  free(node);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Stat information

static inline mode_t normalize_mode(mode_t mode, mode_t default_mt,
                                    bool force) {
  mode_t mt;

  mt = mode & S_IFMT;
  if (force || !mt || mt == S_IFCHR || mt == S_IFBLK ||
      mt == S_IFIFO || mt == S_IFSOCK) {
    mode &= ~S_IFMT;
    mode |= default_mt;
  }
  return mode;
}

void vfs_stat_translate(struct stat *dst, struct vfs_inode_data *src) {
  memset(dst, 0, sizeof(*dst));

  #define M(x) dst->st_##x = src->x
  M(mode),   M(uid),    M(gid),
  M(dev),    M(rdev),   M(size),
  M(atime),   M(mtime),  M(ctime),
  M(ino);
  #undef M

  dst->st_nlink = 1;
  dst->st_blksize = VFS_FAKE_BLOCK_SIZE;
  dst->st_blocks = ((dst->st_size + VFS_FAKE_REPORT_SIZE - 1) &
                   ~(VFS_FAKE_REPORT_SIZE - 1)) / VFS_FAKE_REPORT_SIZE;
  dst->st_mode = normalize_mode(dst->st_mode, S_IFREG, false);
}

void vfs_stat_copy(struct vfs_inode_data *dst, struct vfs_inode_data *src) {
  char name[VFS_PATH_MAX];

  memcpy(name, dst->name, sizeof(dst->name));
  memcpy(dst, src, sizeof(*dst));
  memcpy(dst->name, name, sizeof(dst->name));
}

////////////////////////////////////////////////////////////////////////////////
// Section:     File descriptor functions

vfs_fd_handle vfs_fd_create(struct vfs_inode *node) {
  struct vfs_fd *fd;

  if (!(fd = calloc(sizeof(*fd), 1)))
    stderror("calloc");
  fd->fh = unique_id();
  memcpy(&fd->node, node, sizeof(fd->node));  // TODO: Should consolidate nodes
  fd->prev = NULL;
  fd->next = vfs_fd_list;
  if (vfs_fd_list)
    vfs_fd_list->prev = fd;
  vfs_fd_list = fd;
  return fd->fh;
}

struct vfs_inode *vfs_fd_lookup(vfs_fd_handle fh) {
  struct vfs_fd *fd;

  for (fd = vfs_fd_list; fd; fd = fd->next) {
    if (fh == fd->fh)
      return &fd->node;
  }
  return NULL;
}

bool vfs_fd_close(vfs_fd_handle fh) {
  struct vfs_fd *fd;

  for (fd = vfs_fd_list; fd; fd = fd->next) {
    if (fh == fd->fh)
      break;
  }
  if (!fd)
    return false;

  if (fd->prev)
    fd->prev->next = fd->next;
  else
    vfs_fd_list = fd->next;
  if (fd->next)
    fd->next->prev = fd->prev;
  free(fd);
  return true;
}

void vfs_fd_clear() {
  struct vfs_fd *fd;

  while (vfs_fd_list) {
    fd = vfs_fd_list;
    vfs_fd_list = fd->next;

    free(fd);
  }
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Perform IO operation

int vfs_io_perform(struct vfs_inode *node, enum vfs_io_type type, char *buf,
                   uint64_t size, off_t offset) {
  struct volume_object object;
  uint64_t chunk;
  uint32_t nlen, offt;
  int ret;

  object.index = node->data.ino;
  while (size) {
    chunk = offset >> OBJECT_MAX_SIZE_LOG2;
    offt  = offset & ((1 << OBJECT_MAX_SIZE_LOG2) - 1);
    nlen  = min(OBJECT_MAX_SIZE - offt, size);

    object.chunk = chunk;
    switch (type) {
      case VFS_IO_READ:
        if ((ret = object_read(object, offt, buf, nlen, NULL)) != SUCCESS) {
          if (ret == NOT_FOUND) {
            memset(buf, 0, nlen);
          } else {
            warning("Object read error on %016" PRIx64 ":%u: %d",
                    node->data.ino, offt, ret);
            return -EFAULT;
          }
        }
        break;

      case VFS_IO_WRITE:
        if ((ret = object_write(object, offt, buf, nlen)) != SUCCESS) {
          warning("Object write error on %016" PRIx64 ":%u: %d",
                  node->data.ino, offt, ret);
          return -EFAULT;
        }
        break;
    }

    size   -= nlen;
    offset += nlen;
    buf    += nlen;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Filesystem calls

int vfs_fuse_getattr(const char *path, struct stat *stbuf) {
  struct vfs_inode *node;
  int ret;

  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  vfs_stat_translate(stbuf, &node->data);
  vfs_node_free(node);
  return 0;
}

int vfs_fuse_fgetattr(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi) {
  struct vfs_inode *node;

  if (!(node = vfs_fd_lookup(fi->fh)))
    return -ENOENT;

  vfs_stat_translate(stbuf, &node->data);
  return 0;
}

int vfs_fuse_access(const char *path, int32_t mask) {
  int ret;

  if ((ret = vfs_node_lookup(path, NULL, false)) != 0)
    return ret;
  return 0;
}

int vfs_fuse_readlink(const char *path, char *buf, uint64_t size) {
  struct vfs_inode *node;
  int ret;

  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  if (!S_ISLNK(node->data.mode))
    ret = -EINVAL;
  else
    ret = vfs_io_perform(node, VFS_IO_READ, buf, size, 0);
  vfs_node_free(node);
  return ret;
}

int vfs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                     off_t offset, struct fuse_file_info *fi) {
  struct vfs_inode *node, **list, **lptr;
  struct stat dst;
  int ret;

  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  if (!S_ISDIR(node->data.mode)) {
    vfs_node_free(node);
    return -EINVAL;
  }

  vfs_stat_translate(&dst, &node->data);
  filler(buf, ".", &dst, 0);
  filler(buf, "..", NULL, 0);

  if (!(list = vfs_dir_read(node->data.ino, NULL))) {
    warning("File system missing data at inode %016" PRIx64,
            node->data.ino);
    vfs_node_free(node);
    return -EFAULT;
  }

  for (lptr = list; *lptr; lptr++) {
    struct vfs_inode *found_node = *lptr;

    vfs_stat_translate(&dst, &found_node->data);
    filler(buf, found_node->data.name, &dst, 0);
  }

  vfs_dir_read_free(list);
  vfs_node_free(node);
  return 0;
}

int vfs_fuse_mknod(const char *path, mode_t mode, dev_t rdev) {
  struct vfs_inode *node;
  struct fuse_context *ctx;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if (!(ctx = fuse_get_context()))
    return -EFAULT;

  if ((ret = vfs_node_lookup(path, &node, true)) != 0)
    return ret;

  node->data.mode = normalize_mode(mode, S_IFREG, false);
  node->data.rdev = rdev;
  node->data.uid  = ctx->uid;
  node->data.gid  = ctx->gid;
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_mkdir(const char *path, mode_t mode) {
  struct vfs_inode *node;
  struct fuse_context *ctx;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if (!(ctx = fuse_get_context()))
    return -EFAULT;

  if ((ret = vfs_node_lookup(path, &node, true)) != 0)
    return ret;

  node->data.mode = normalize_mode(mode, S_IFDIR, true);
  node->data.uid  = ctx->uid;
  node->data.gid  = ctx->gid;
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  struct vfs_inode *node;
  struct fuse_context *ctx;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if (!(ctx = fuse_get_context()))
    return -EFAULT;

  if ((ret = vfs_node_lookup(path, &node, true)) != 0)
    return ret;

  node->data.mode = normalize_mode(mode, S_IFREG, false);
  node->data.uid  = ctx->uid;
  node->data.gid  = ctx->gid;

  fi->fh = vfs_fd_create(node);
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_unlink(const char *path) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  if ((ret = vfs_node_delete(node)) != 0) {
    vfs_node_free(node);
    return ret;
  }
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_rmdir(const char *path) {
  struct vfs_inode *node, **list;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  if (!S_ISDIR(node->data.mode)) {
    vfs_node_free(node);
    return -ENOTDIR;
  }

  if (!(list = vfs_dir_read(node->data.ino, NULL))) {
    warning("File system missing data at inode %016" PRIx64,
            node->data.ino);
    vfs_node_free(node);
    return -EFAULT;
  }

  if (*list) {
    ret = -ENOTEMPTY;
  } else {
    if ((ret = vfs_node_delete(node)) == 0)
      ret = vfs_node_commit(node);
  }

  vfs_dir_read_free(list);
  vfs_node_free(node);
  return ret;
}

int vfs_fuse_symlink(const char *from, const char *to) {
  struct vfs_inode *node;
  struct fuse_context *ctx;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if (!(ctx = fuse_get_context()))
    return -EFAULT;

  if ((ret = vfs_node_lookup(to, &node, true)) != 0)
    return ret;

  node->data.mode = S_IFLNK | VFS_DEFAULT_MODE;
  node->data.uid  = ctx->uid;
  node->data.gid  = ctx->gid;

  if ((ret = vfs_io_perform(node, VFS_IO_WRITE, (char*) from,
                            strlen(from), 0)) != 0) {
    vfs_node_free(node);
    return ret;
  }
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_rename(const char *from, const char *to) {
  struct vfs_inode *node, *new_node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(from, &node, false)) != 0)
    return ret;

  if ((ret = vfs_node_lookup(to, &new_node, true)) != 0) {
    if (ret != -EEXIST)
      return ret;
    if ((ret = vfs_fuse_unlink(to)) != 0)
      return ret;
    if ((ret = vfs_node_lookup(to, &new_node, true)) != 0)
      return ret;
  }

  vfs_stat_copy(&new_node->data, &node->data);
  if ((ret = vfs_node_commit_and_free(new_node)) != 0)
    return ret;

  node->data.flag &= ~VFS_INODE_FLAG_VALID;
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_link(const char *from, const char *to) {
  return -ENOTSUP;
}

int vfs_fuse_chmod(const char *path, mode_t mode) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  node->data.mode = normalize_mode(mode, S_IFREG, false);
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_chown(const char *path, uid_t uid, gid_t gid) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  node->data.uid = uid;
  node->data.gid = gid;
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_truncate(const char *path, off_t size) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  if (node->data.size == size)
    return 0;

  node->data.size  = size;
  node->data.mtime = time(NULL);
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_ftruncate(const char *path, off_t size,
                       struct fuse_file_info *fi) {
  struct vfs_inode *node;

  if (store_get_readonly())
    return -EPERM;
  if (!(node = vfs_fd_lookup(fi->fh)))
    return -ENOENT;

  if (node->data.size == size)
    return 0;

  node->data.size = size;
  node->modified  = true;
  return 0;
}

int vfs_fuse_utime(const char *path, struct utimbuf *buf) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  node->data.atime = buf->actime;
  node->data.mtime = buf->modtime;
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_utimens(const char *path, const struct timespec ts[2]) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  node->data.atime = ts[0].tv_sec;
  node->data.mtime = ts[1].tv_sec;
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_open(const char *path, struct fuse_file_info *fi) {
  struct vfs_inode *node;
  int ret;

  if ((ret = vfs_node_lookup(path, &node, false)) != 0)
    return ret;

  if (!S_ISLNK(node->data.mode) && !S_ISREG(node->data.mode)) {
    vfs_node_free(node);
    return -EISDIR;
  }

  fi->fh = vfs_fd_create(node);
  return vfs_node_commit_and_free(node);
}

int vfs_fuse_read(const char *path, char *buf, uint64_t size,
                  off_t offset, struct fuse_file_info *fi) {
  struct vfs_inode *node;
  int ret;

  if (!(node = vfs_fd_lookup(fi->fh)))
    return -ENOENT;

  if ((ret = vfs_io_perform(node, VFS_IO_READ, buf, size, offset)) != 0)
    return ret;
  return size;
}

int vfs_fuse_write(const char *path, const char *buf, uint64_t size,
                   off_t offset, struct fuse_file_info *fi) {
  struct vfs_inode *node;
  int ret;

  if (store_get_readonly())
    return -EPERM;
  if (!(node = vfs_fd_lookup(fi->fh)))
    return -ENOENT;

  node->data.size       = max(node->data.size,       size + offset);
  node->data.last_block = max(node->data.last_block, size + offset);
  node->modified        = true;
  if ((ret = vfs_io_perform(node, VFS_IO_WRITE, (char*) buf, size,
                            offset)) != 0)
    return ret;
  return size;
}

int vfs_fuse_flush(const char *path, struct fuse_file_info *fi) {
  struct vfs_inode *node;
  uint64_t size, last_block;
  int ret;

  if (!(node = vfs_fd_lookup(fi->fh)))
    return -ENOENT;

  if (!node->modified)
    return 0;

  size       = node->data.size;
  last_block = node->data.last_block;
  if ((ret = vfs_node_rehash(node)) != 0)
    return ret;

  node->data.size       = size;
  node->data.last_block = max(node->data.last_block, last_block);
  node->data.mtime      = time(NULL);
  return vfs_node_commit(node);
}

int vfs_fuse_release(const char *path, struct fuse_file_info *fi) {
  if (!vfs_fd_close(fi->fh))
    return -EFAULT;
  return 0;
}

int vfs_fuse_fsync(const char *path, int32_t isdatasync,
                   struct fuse_file_info *fi) {
  return vfs_fuse_flush(path, fi);
}

int vfs_fuse_statfs(const char *path, struct statvfs *stbuf) {
  stbuf->f_bsize   = OBJECT_MAX_SIZE;
  stbuf->f_frsize  = OBJECT_MAX_SIZE;
  stbuf->f_blocks  = -1;
  stbuf->f_bfree   = -1;
  stbuf->f_bavail  = -1;
  stbuf->f_files   = 0;
  stbuf->f_ffree   = 0;
  stbuf->f_favail  = 0;
  stbuf->f_fsid    = vfs_fsid;
  stbuf->f_flag    = 0;
  stbuf->f_namemax = VFS_PATH_MAX;
  return 0;
}

#endif
