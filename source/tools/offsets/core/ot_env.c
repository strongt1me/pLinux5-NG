/*
 * ot_env.c -- globals + userland helpers for the offsets tool's XOM-defeat
 * stage. Mirrors the parts of pLinux5-NG's source/core/utils.c that the
 * vendored Byepervisor modules depend on, without pulling in the Linux-boot
 * machinery.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "ot_env.h"

#include "escape.h"
#include "utils.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/cpuset.h>
#include <unistd.h>

/* Globals expected by the vendored modules (declared extern in utils.h). */
offset_list env_offset;
uint64_t ktext;
uint64_t kdata;
uint64_t dmap;
uint64_t cr3;
uint32_t fw;
uint64_t vmcb_pa[16];
struct linux_info linux_i;

void ot_env_sync(void) {
  ktext = ot_ktext;
  kdata = ot_kdata;
  dmap = ot_dmap;
  cr3 = ot_cr3;
  fw = ot_fwsel;
}

/* --------------------------------------------------------------- logging -- */
#define OT_LOG_MAX 6
static int g_log_fd[OT_LOG_MAX];
static int g_log_append = 0;
static const char *const g_log_paths[] = {
    "/mnt/usb0/pl5_offsets.log", "/mnt/usb1/pl5_offsets.log",
    "/mnt/usb2/pl5_offsets.log", "/mnt/usb3/pl5_offsets.log",
    "/data/pl5_offsets.log",    "/tmp/pl5_offsets.log",
    NULL,
};

void log_reopen(void) {
  for (int i = 0; i < OT_LOG_MAX; i++)
    g_log_fd[i] = 0;
  g_log_append = 1;
}

static void ot_log_write(const char *msg) {
  for (int i = 0; g_log_paths[i]; i++) {
    if (g_log_fd[i] == 0) {
      int flags = O_WRONLY | O_CREAT | (g_log_append ? O_APPEND : O_TRUNC);
      int fd = open(g_log_paths[i], flags, 0644);
      if (fd > 0)
        g_log_fd[i] = fd;
    }
  }
  for (int i = 0; g_log_paths[i]; i++) {
    if (g_log_fd[i] > 0) {
      write(g_log_fd[i], msg, strlen(msg));
      fsync(g_log_fd[i]);
    }
  }
}

void notify_internal(uint8_t *msg) {
  struct {
    char pad[45];
    char msg[3075];
  } req;
  memset(&req, 0, sizeof(req));
  size_t len = strlen((const char *)msg);
  if (len > sizeof(req.msg) - 1)
    len = sizeof(req.msg) - 1;
  memcpy(req.msg, msg, len);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

void notify(const char *fmt, ...) {
  static char buffer[2048];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  notify_internal((uint8_t *)buffer);
  printf("%s", buffer);
  fflush(stdout);
  ot_log_write(buffer);
}

void logmsg(const char *fmt, ...) {
  static char buffer[2048];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  printf("%s", buffer);
  fflush(stdout);
  ot_log_write(buffer);
}

/* ------------------------------------------------------- core / rest mode -- */
int pin_to_core(int n) {
  uint64_t m[2] = {0};
  /* Sony numbers CPUs in reverse: logical core N is physical bit (15 - N). */
  m[0] = 1ULL << (15 - n);
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)m);
}

void unpin(void) {
  uint64_t m[2] = {0xFFFF, 0};
  cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)m);
}

void enter_rest_mode(void) {
  void *event = NULL;
  sceKernelOpenEventFlag(&event, "SceSystemStateMgrStatus");
  sceKernelNotifySystemSuspendStart();
  sceKernelSetEventFlag(event, 0x400);
  sceKernelCloseEventFlag(&event);
}

uint64_t pa_to_dmap(uint64_t pa) { return dmap + pa; }
