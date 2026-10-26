/*
 * escape.c -- firmware-agnostic kernel bootstrap for the offsets tool.
 * See escape.h.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "escape.h"

#include "ot_find.h"

#include <ps5/kernel.h>
#include <ps5/payload.h>

uint64_t ot_kdata;
uint32_t ot_fw;
uint32_t ot_fwsel;
uint64_t ot_pmap;
uint64_t ot_cr3;
uint64_t ot_dmap;
uint64_t ot_ktext;

#define PA_MASK 0x000FFFFFFFFFF000ULL
#define PTE_P 0x1ULL
#define PTE_PS 0x80ULL   /* huge page (PDPT/PD level) */
#define PTE_XO (1ULL << 58) /* eXecute-Only / XOTEXT */

int ot_rd(uint64_t va, void *dst, size_t len) {
  if (!va)
    return -1;
  return kernel_copyout((intptr_t)va, dst, len);
}

int ot_bootstrap(void) {
  payload_args_t *args = payload_get_args();
  if (!args || !args->kdata_base_addr)
    return -1;
  ot_kdata = (uint64_t)args->kdata_base_addr;

  ot_fw = kernel_get_fw_version();
  ot_fwsel = ot_fw >> 16;

  /* Firmware 2.70 and below: the SDK-reported data anchor differs from the
   * kernel-image anchor the rest of the pipeline assumes. (We target 8.xx+, but
   * keep this for completeness.) */
  if (ot_fwsel <= 0x270)
    ot_kdata -= 0x1010000;

  /* Discover the kernel pmap from the pmap invariant plus a direct-map
   * round-trip of a kernel-data byte: no per-firmware offset, no .text read. */
  if (ot_find_pmap() != 0)
    return -3;

  if (!ot_pmap || !ot_cr3 || !ot_dmap)
    return -3;

  /* Derive ktext from the validated page tables (may be 0 if unmapped). */
  ot_ktext = ot_find_ktext();

  return 0;
}

/* --------------------------------------------------------- page tables --- */

static uint64_t pv_rd64(uint64_t a) {
  uint64_t v = 0;
  kernel_copyout((intptr_t)a, &v, sizeof(v));
  return v;
}

/* Leaf PTE for `va` in the kernel pmap (0 if not present). Walks the tables via
 * the direct map, so it never touches an unmapped VA. */
static uint64_t leaf_entry(uint64_t va) {
  uint64_t tbl = ot_cr3 & PA_MASK;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t e = pv_rd64(ot_dmap + tbl + idx * 8);

    if (!(e & PTE_P))
      return 0;

    if ((level == 1 || level == 2) && (e & PTE_PS))
      return e; /* 1 GiB / 2 MiB page covers the whole range */
    if (level == 3)
      return e;

    tbl = e & PA_MASK;
  }
  return 0;
}

uint64_t ot_vtophys(uint64_t va) {
  uint64_t tbl = ot_cr3 & PA_MASK;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t e = pv_rd64(ot_dmap + tbl + idx * 8);

    if (!(e & PTE_P))
      return 0;

    if ((level == 1 || level == 2) && (e & PTE_PS)) {
      uint64_t page = (level == 1) ? (1ULL << 30) : (1ULL << 21);
      return (e & PA_MASK) | (va & (page - 1));
    }
    if (level == 3)
      return (e & PA_MASK) | (va & 0xFFF);

    tbl = e & PA_MASK;
  }
  return 0;
}

int ot_page_mapped(uint64_t va) {
  return (leaf_entry(va & ~0xFFFULL) & PTE_P) != 0;
}

int ot_page_readable(uint64_t va) {
  uint64_t e = leaf_entry(va & ~0xFFFULL);
  return (e & PTE_P) && !(e & PTE_XO);
}

size_t ot_kread(uint64_t va, void *dst, size_t len) {
  uint8_t *p = dst;
  size_t done = 0;

  while (done < len) {
    uint64_t a = va + done;
    size_t page_left = 0x1000 - (a & 0xFFF);
    size_t n = len - done < page_left ? len - done : page_left;

    if (!ot_page_readable(a))
      break;

    if (kernel_copyout((intptr_t)a, p + done, n) != 0)
      break;
    done += n;
  }
  return done;
}

int ot_readable(uint64_t va, size_t len) {
  uint8_t probe[0x100];
  while (len) {
    size_t n = len < sizeof(probe) ? len : sizeof(probe);
    if (ot_kread(va, probe, n) != n)
      return 0;
    va += n;
    len -= n;
  }
  return 1;
}
