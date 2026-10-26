/*
 * escape.h -- firmware-agnostic kernel bootstrap for the offsets tool.
 *
 * The only runtime anchor we trust is the loader-provided kernel data base
 * (payload_args_t.kdata_base_addr); everything else is discovered from the
 * kernel's own data structures. There is no per-firmware offset table: the
 * bootstrap never reads kernel .text, so it works while .text is execute-only,
 * on any firmware 8.xx..13.xx.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Loader-provided kernel data anchor (payload_args_t.kdata_base_addr). */
extern uint64_t ot_kdata;

/* Running firmware version (full, e.g. 0x13600007) and its selector (>>16). */
extern uint32_t ot_fw;
extern uint32_t ot_fwsel;

/* Kernel pmap anchors, derived from data-side anchors only (no .text). */
extern uint64_t ot_pmap; /* address of the kernel pmap struct */
extern uint64_t ot_cr3;  /* pmap->pm_cr3 */
extern uint64_t ot_dmap; /* pmap->pm_pml4 - pmap->pm_cr3 */

/* Kernel text base, derived by walking the kernel page tables (0 until known). */
extern uint64_t ot_ktext;

/* Resolve a kdata-relative offset to an absolute VA. Pure arithmetic -- no
 * kernel memory is touched. */
static inline uint64_t ot_kaddr(int64_t off) {
  return ot_kdata + (uint64_t)off;
}

/* Phase 0: anchors only. Resolves kdata_base, discovers the kernel pmap from
 * the pmap invariant, then derives ktext from the page tables. Performs NO
 * writes and reads NOTHING inside kernel .text. Returns 0 on success, <0:
 *   -1  no loader anchor
 *   -3  pmap anchors unavailable */
int ot_bootstrap(void);

/* Safe data read via kernel_copyout. Returns 0 on success. Callers MUST NOT
 * use this on .text before XOM has been defeated. */
int ot_rd(uint64_t va, void *dst, size_t len);
static inline uint64_t ot_rd64(uint64_t va) {
  uint64_t v = 0;
  ot_rd(va, &v, sizeof(v));
  return v;
}

/* --- page-table helpers (data-only; used by later dump stages) ------------ */

/* Kernel VA -> PA using the running pmap. 0 if unmapped. */
uint64_t ot_vtophys(uint64_t va);

/* Leaf-entry probes (page granularity, no copyout). */
int ot_page_mapped(uint64_t va);
int ot_page_readable(uint64_t va);

/* Page-safe bounded copyout: stops at the first unmapped or XOM page. Returns
 * bytes read. Safe against .text (stops rather than faulting). */
size_t ot_kread(uint64_t va, void *dst, size_t len);

/* True if [va, va+len) is fully mapped + readable in the kernel pmap. */
int ot_readable(uint64_t va, size_t len);
