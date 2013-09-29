/*
 * cloudfs: block header
 *	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#pragma once

////////////////////////////////////////////////////////////////////////////////
// Section:     Required includes

#include "volume.h"

////////////////////////////////////////////////////////////////////////////////
// Section:     Macros

#define BLOCK_THREAD_STACK_SIZE		(1 * 1024 * 1024)

#define BLOCK_NBD_SIZE			4096
#define BLOCK_NBD_SIZE_LOG2		12

#define BLOCK_LOCAL_IP			"127.0.0.1"

////////////////////////////////////////////////////////////////////////////////
// Section:     Format table

extern const struct volume_intr block_intr;

////////////////////////////////////////////////////////////////////////////////
// Section:     Connect to nbd

void block_mount(const struct volume_metadata *md, const char *path);
void block_unmount(const struct volume_metadata *md, const char *path);

////////////////////////////////////////////////////////////////////////////////
// Section:     Disconnect from nbd

void block_disconnect();

////////////////////////////////////////////////////////////////////////////////
// Section:     Modprobe

void block_nbd_modprobe();

////////////////////////////////////////////////////////////////////////////////
// Section:     Signal handling

void block_nbd_signal();
void block_nbd_signal_handler(int signal);

////////////////////////////////////////////////////////////////////////////////
// Section:     Local connection for NBD device

void block_nbd_setup();
int32_t block_nbd_listen_rand_port();
int32_t block_nbd_accept(int32_t lfd);
int32_t block_nbd_connect();
void block_nbd_tcp_nodelay(int32_t fd);
void block_nbd_spawn_thread();
void block_nbd_thread_doit(void *__unused);
void block_nbd_thread_sync(void *__unused);

////////////////////////////////////////////////////////////////////////////////
// Section:     Process nbd requests

void block_nbd_process();
bool block_nbd_read(void *data, size_t len);
bool block_nbd_write(void *data, size_t len);
int block_nbd_commit_object(uint32_t type, char *p_buf, uint32_t p_len, uint64_t p_from);
