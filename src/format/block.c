/*
 * cloudfs: block source
 *   By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/nbd.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "config.h"
#include "log.h"
#include "object.h"
#include "store.h"
#include "misc.h"
#include "format/block.h"

////////////////////////////////////////////////////////////////////////////////
// Class:       block
// Description: Block storage format

////////////////////////////////////////////////////////////////////////////////
// Section:     Format table

const struct volume_intr block_intr = {
  .mount    = block_mount,
  .unmount  = block_unmount,

  .flags    = VOLUME_NEED_SIZE,
};

////////////////////////////////////////////////////////////////////////////////
// Section:     Global variables

static int32_t block_nbd_fd = -1, block_nbd_dev = -1;

static uint32_t block_nbd_port = 0;

////////////////////////////////////////////////////////////////////////////////
// Section:     Connect to nbd

void block_mount(const struct volume_metadata *md, const char *path) {
  uint32_t blocks;

  block_nbd_modprobe();

  if ((md->capacity & ((1 << BLOCK_NBD_SIZE_LOG2) - 1)))
    error("Invalid size specified for volume, "
          "size must be multiple of block size %d",
          BLOCK_NBD_SIZE);

  blocks = (md->capacity >> BLOCK_NBD_SIZE_LOG2);

  if ((block_nbd_dev = open(path, O_RDWR)) < 0)
    error("Unable to open nbd device %s, "
          "you must be root to open /dev/nbd*", path);

  if (ioctl(block_nbd_dev, NBD_SET_BLKSIZE, BLOCK_NBD_SIZE) < 0 ||
      ioctl(block_nbd_dev, NBD_SET_SIZE_BLOCKS, blocks) < 0)
    error("Error communicating with nbd device %s", path);

  notice("Volume mounting on %s", path);

  if (!config_get("nofork")) {
    if (fork())
      exit(0);
  }

  object_load();
  block_nbd_setup();
  block_nbd_signal();
  block_nbd_process();

  notice("Volume disconnecting");

  block_disconnect();
  object_unload();
}

void block_unmount(const struct volume_metadata *md, const char *path) {
  if ((block_nbd_dev = open(path, O_RDWR)) < 0)
    error("Unable to open nbd device %s, "
          "you must be root to open /dev/nbd*", path);

  block_disconnect();
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Disconnect from nbd

void block_disconnect() {
  if (block_nbd_dev >= 0) {
    ioctl(block_nbd_dev, NBD_CLEAR_QUE);
    ioctl(block_nbd_dev, NBD_DISCONNECT);
    ioctl(block_nbd_dev, NBD_CLEAR_SOCK);
    close(block_nbd_dev);
    block_nbd_dev = -1;
  }

  if (block_nbd_fd >= 0) {
    close(block_nbd_fd);
    block_nbd_fd = -1;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Modprobe

void block_nbd_modprobe() {
  pid_t pid;

  if (!(pid = fork())) {
    execlp("/sbin/modprobe", "modprobe", "nbd", NULL);
    exit(0);
  }
  waitpid(pid, NULL, 0);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Signal handling

void block_nbd_signal() {
  signal(SIGHUP,  block_nbd_signal_handler);
  signal(SIGINT,  block_nbd_signal_handler);
  signal(SIGQUIT, block_nbd_signal_handler);
  signal(SIGTERM, block_nbd_signal_handler);
}

void block_nbd_signal_handler(int signal) {
  if (block_nbd_dev >= 0)
    ioctl(block_nbd_dev, NBD_DISCONNECT);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Local connection for NBD device

void block_nbd_setup() {
  int32_t lfd, cfd;

  lfd = block_nbd_listen_rand_port();
  cfd = block_nbd_connect();
  block_nbd_fd = block_nbd_accept(lfd);
  close(lfd);

  ioctl(block_nbd_dev, NBD_CLEAR_SOCK);
  if (ioctl(block_nbd_dev, NBD_SET_SOCK, cfd) < 0)
    error("Unable to set socket for local device");

  block_nbd_spawn_thread();
}

int32_t block_nbd_listen_rand_port() {
  int32_t fd, i;
  bool found_port;
  struct sockaddr_in lin;

  if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    error("Unable to create local socket");

  found_port = false;

  lin.sin_family = AF_INET;
  lin.sin_addr.s_addr = inet_addr(BLOCK_LOCAL_IP);
  for (i = 0; i < 10; i++) {
    block_nbd_port = (rand() % 31744) + 1024;

    lin.sin_port = htons(block_nbd_port);
    if (bind(fd, (struct sockaddr*) &lin, sizeof(lin)) < 0)
      continue;
    if (listen(fd, SOMAXCONN) < 0)
      continue;
    found_port = true;
    break;
  }
  if (!found_port)
    error("Unable to listen on local socket");
  return fd;
}

int32_t block_nbd_accept(int32_t lfd) {
  int32_t fd;
  struct sockaddr_in in;
  socklen_t in_len;

  in_len = sizeof(in);
  if ((fd = accept(lfd, (struct sockaddr*) &in, &in_len)) < 0)
    error("Unable to accept from local socket");

  block_nbd_tcp_nodelay(fd);
  return fd;
}

int32_t block_nbd_connect() {
  int32_t fd;
  struct sockaddr_in in;

  if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    error("Unable to create local socket");

  in.sin_family = AF_INET;
  in.sin_addr.s_addr = inet_addr(BLOCK_LOCAL_IP);
  in.sin_port = htons(block_nbd_port);
  if (connect(fd, (struct sockaddr*) &in, sizeof(in)) < 0)
    error("Unable to connect to local socket");

  block_nbd_tcp_nodelay(fd);
  return fd;
}

void block_nbd_tcp_nodelay(int32_t fd) {
  uint32_t tcp_flag;

  tcp_flag = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
      &tcp_flag, sizeof(tcp_flag));
}

void block_nbd_spawn_thread() {
  pthread_t pid;
  pthread_attr_t pattr;

  pthread_attr_init(&pattr);
  pthread_attr_setstacksize(&pattr, BLOCK_THREAD_STACK_SIZE);
  pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);

  pthread_create(&pid, &pattr, (void *(*)(void*)) block_nbd_thread_doit, NULL);
#ifdef LOAD_PARTITION_TABLE
  pthread_create(&pid, &pattr, (void *(*)(void*)) block_nbd_thread_sync, NULL);
#endif

  pthread_attr_destroy(&pattr);
}

void block_nbd_thread_doit(void *__unused) {
  ioctl(block_nbd_dev, NBD_DO_IT);
}

void block_nbd_thread_sync(void *__unused) {
  sleep(1);
  sync();
  ioctl(block_nbd_dev, BLKRRPART);
}

////////////////////////////////////////////////////////////////////////////////
// Section:     Process nbd requests

void block_nbd_process() {
  char *data;
  uint32_t data_len;
  uint32_t type;
  uint64_t from;
  struct nbd_request req;
  struct nbd_reply repl;
  int ret;

  while (1) {
    if (!block_nbd_read(&req, sizeof(req))) {
      warning("An error occured while reading from nbd");
      break;
    }
    if (ntohl(req.magic) != NBD_REQUEST_MAGIC) {
      warning("NBD req magic (0x%08x) doesnt match one supplied by "
              "kernel (0x%08x)", NBD_REQUEST_MAGIC, ntohl(req.magic));
      continue;
    }

    type = ntohl(req.type);

    if (type == NBD_CMD_READ || type == NBD_CMD_WRITE) {
      data_len = ntohl(req.len);
      from = be64toh(req.from);

      if (!(data = malloc(data_len)))
        stderror("malloc");
      if (type == NBD_CMD_WRITE) {
        if (!block_nbd_read(data, data_len)) {
          warning("An error occured while reading from nbd");
          free(data);
          break;
        }
      }

      ret = block_nbd_commit_object(type, data, data_len, from);

      repl.magic = htonl(NBD_REPLY_MAGIC);
      repl.error = htonl(-ret);
      memcpy(repl.handle, req.handle, sizeof(repl.handle));

      if (!block_nbd_write(&repl, sizeof(repl))) {
        warning("An error occured while writing to nbd");
        free(data);
        break;
      }
      if (ret == 0 && type == NBD_CMD_READ) {
        if (!block_nbd_write(data, data_len)) {
          warning("An error occured while writing to nbd");
          free(data);
          break;
        }
      }

      free(data);
    } else if (type == NBD_CMD_DISC) {
      break;
    } else {
      error("Invalid command from nbd %d", type);
    }
  }
}

bool block_nbd_read(void *data, size_t len) {
  ssize_t rlen;

  while (1) {
    rlen = recv(block_nbd_fd, data, len, MSG_WAITALL);
    if (rlen < len) {
      if (!rlen || (rlen < 0 && errno != EINTR))
        return false;
      if (rlen > 0) {
        data += rlen;
        len  -= rlen;
      }
      continue;
    }
    break;
  }
  return true;
}

bool block_nbd_write(void *data, size_t len) {
  ssize_t rlen;

  while (1) {
    rlen = send(block_nbd_fd, data, len, 0);
    if (rlen < len) {
      if (rlen < 0 && errno != EINTR)
        return false;
      if (rlen > 0) {
        data += rlen;
        len  -= rlen;
      }
      continue;
    }
    break;
  }
  return true;
}

int block_nbd_commit_object(uint32_t type, char *p_buf, uint32_t p_len,
                            uint64_t p_from) {
  struct volume_object object;
  uint64_t ident;
  uint32_t nlen, offt;
  int ret;

  if (type == NBD_CMD_WRITE && store_get_readonly())
    return -EPERM;

  object.index = 0;
  while (p_len) {
    ident = p_from >> OBJECT_MAX_SIZE_LOG2;
    offt  = p_from & ((1 << OBJECT_MAX_SIZE_LOG2) - 1);
    nlen  = min(OBJECT_MAX_SIZE - offt, p_len);

    object.chunk = ident;
    switch (type) {
      case NBD_CMD_READ:
        if ((ret = object_read(object, offt, p_buf, nlen, NULL)) != SUCCESS) {
          if (ret == NOT_FOUND) {
            memset(p_buf, 0, nlen);
          } else {
            warning("Object read error on %016" PRIx64 ":%u: %d",
                    ident, offt, ret);
            return -EFAULT;
          }
        }
        break;

      case NBD_CMD_WRITE:
        if ((ret = object_write(object, offt, p_buf, nlen)) != SUCCESS) {
          warning("Object write error on %016" PRIu64 ":%u: %d",
                  ident, offt, ret);
          return -EFAULT;
        }
        break;
    }

    p_len  -= nlen;
    p_from += nlen;
    p_buf  += nlen;
  }
  return 0;
}
