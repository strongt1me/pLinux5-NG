/*
 * ot_harvest.h -- data-side kernel-text anchor harvest.
 *
 * The blind-bootstrap method needs text addresses (function entries) without
 * reading text. Many already exist as pointers *inside data we can read*:
 * every sysent entry's sy_call, every IDT handler, and any function-pointer
 * table in the image. Harvesting them gives:
 *
 *   - an independent cross-check of ktext (the lowest harvested pointer must be
 *     at or above ktext and within K of it),
 *   - a pool of candidate kernel function entries that the execution oracle can
 *     then validate one instruction at a time.
 *
 * Nothing here reads kernel .text; only pointers held in data.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#pragma once

#include <stdint.h>

struct ot_harvest {
  uint64_t sys_calls;     /* in-range sy_call pointers from sysentvec */
  uint64_t idt_handlers;  /* in-range handlers from the 256 IDT gates */
  uint64_t sweep_ptrs;    /* in-range pointers found in the bounded sweep */
  uint64_t tables;        /* function-pointer runs (stride 8, len >= min) */
  uint64_t table_max;     /* longest such run */
  uint64_t table_max_off; /* kdata-relative offset of the longest run */
  uint64_t ptr_min;       /* lowest in-range text pointer seen anywhere */
  uint64_t ptr_max;       /* highest */
  int ktext_ok;           /* ptr_min >= ktext */
  uint64_t ktext_gap;     /* ptr_min - ktext (0 if ktext underivable) */
};

/* Harvest using the discovered sysentvec table and IDT offset. `sv_table` is
 * absolute; `idt_off` is kdata-relative. Safe to call when either is 0. */
void ot_harvest_run(uint64_t sv_table, uint64_t sv_size, uint64_t idt_off,
                    struct ot_harvest *h);
