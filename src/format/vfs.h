/*
 * cloudfs: vfs header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#define FUSE_USE_VERSION 26
#include <sys/stat.h>
#include <fuse.h>
#include "volume.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define VFS_PATH_SEPERATOR	'/'
#define VFS_PATH_MAX		128

#define VFS_DEFAULT_MODE	0644

#define VFS_FAKE_BLOCK_SIZE	4096
#define VFS_FAKE_REPORT_SIZE	512

////////////////////////////////////////////////////////////////////////////////
// Section:     Format table

extern const struct volume_intr vfs_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     Inode data

enum vfs_inode_flag {
	VFS_INODE_FLAG_VALID	= 1 << 0,
};

struct vfs_inode_data {
	char name[VFS_PATH_MAX];
	uint64_t ino, last_block;
	uint32_t flag;
	
	uint32_t mode, uid, gid;
	uint64_t dev, rdev, nlink, size;
	uint64_t atime, mtime, ctime;
} __attribute__((packed));

struct vfs_inode_ptr {
	struct volume_object object;
	uint32_t offt;
};

struct vfs_inode {
	struct vfs_inode_data data;
	struct vfs_inode_ptr ptr;
	bool is_root, modified, new_file;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     File descriptor information

typedef uint64_t vfs_fd_handle;

struct vfs_fd {
	vfs_fd_handle fh;
	struct vfs_inode node;
	struct vfs_fd *prev, *next;
};

////////////////////////////////////////////////////////////////////////////////
// Section:     File descriptor information

enum vfs_io_type {
	VFS_IO_READ,
	VFS_IO_WRITE,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Call vfs

void vfs_mount(const struct volume_metadata *md, const char *path);
void vfs_unmount(const struct volume_metadata *md, const char *path);

////////////////////////////////////////////////////////////////////////////////
// Section:     Path parsing

char **vfs_path_split(char *str);
void vfs_path_split_free(char **dst);

////////////////////////////////////////////////////////////////////////////////
// Section:     Directory operations

struct vfs_inode **vfs_dir_read(uint64_t inode, struct vfs_inode_ptr *empty_ptr);
bool vfs_dir_read_pass(struct vfs_inode_ptr *ptr, struct vfs_inode_ptr *save_ptr, 
		void *data, uint32_t len);
void vfs_dir_read_free(struct vfs_inode **list);

////////////////////////////////////////////////////////////////////////////////
// Section:     Node lookup

int vfs_node_lookup(const char *path, struct vfs_inode **node, bool new_file);
int vfs_node_rehash(struct vfs_inode *node);
int vfs_node_commit(struct vfs_inode *node);
int vfs_node_commit_and_free(struct vfs_inode *node);
int vfs_node_delete(struct vfs_inode *node);
void vfs_node_free(struct vfs_inode *node);

////////////////////////////////////////////////////////////////////////////////
// Section:     Stat information

void vfs_stat_translate(struct stat *dst, struct vfs_inode_data *src);
void vfs_stat_copy(struct vfs_inode_data *dst, struct vfs_inode_data *src);

////////////////////////////////////////////////////////////////////////////////
// Section:     File descriptor functions

vfs_fd_handle vfs_fd_create(struct vfs_inode *node);
struct vfs_inode *vfs_fd_lookup(vfs_fd_handle fh);
bool vfs_fd_close(vfs_fd_handle fh);
void vfs_fd_clear();

////////////////////////////////////////////////////////////////////////////////
// Section:     Perform IO operation

int vfs_io_perform(struct vfs_inode *node, enum vfs_io_type type, char *buf,
		uint64_t size, off_t offset);

////////////////////////////////////////////////////////////////////////////////
// Section:     Filesystem calls

int vfs_fuse_getattr(const char *path, struct stat *stbuf);
int vfs_fuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
int vfs_fuse_access(const char *path, int32_t mask);
int vfs_fuse_readlink(const char *path, char *buf, uint64_t size);
int vfs_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi);
int vfs_fuse_mknod(const char *path, mode_t mode, dev_t rdev);
int vfs_fuse_mkdir(const char *path, mode_t mode);
int vfs_fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int vfs_fuse_unlink(const char *path);
int vfs_fuse_rmdir(const char *path);
int vfs_fuse_symlink(const char *from, const char *to);
int vfs_fuse_rename(const char *from, const char *to);
int vfs_fuse_link(const char *from, const char *to);
int vfs_fuse_chmod(const char *path, mode_t mode);
int vfs_fuse_chown(const char *path, uid_t uid, gid_t gid);
int vfs_fuse_truncate(const char *path, off_t size);
int vfs_fuse_ftruncate(const char *path, off_t size, struct fuse_file_info *fi);
int vfs_fuse_utime(const char *path, struct utimbuf *buf);
int vfs_fuse_utimens(const char *path, const struct timespec ts[2]);
int vfs_fuse_open(const char *path, struct fuse_file_info *fi);
int vfs_fuse_read(const char *path, char *buf, uint64_t size,
		off_t offset, struct fuse_file_info *fi);
int vfs_fuse_write(const char *path, const char *buf, uint64_t size,
		off_t offset, struct fuse_file_info *fi);
int vfs_fuse_flush(const char *path, struct fuse_file_info *fi);
int vfs_fuse_release(const char *path, struct fuse_file_info *fi);
int vfs_fuse_fsync(const char *path, int32_t isdatasync, struct fuse_file_info *fi);
int vfs_fuse_statfs(const char *path, struct statvfs *stbuf);
