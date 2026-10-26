/*
 * ot_find.h -- data-only symbol discovery for the offsets tool.
 *
 * Every finder locates a kernel-data symbol by a structural invariant of the
 * object itself (or of the pointers that reference it), never by a per-firmware
 * constant and never by reading kernel .text. That keeps the tool correct on
 * any firmware 8.xx..13.xx while .text is still execute-only.
 *
 * Each finder returns a *kdata-relative* offset (0 == not found) so it slots
 * into the same coordinate system as the loader anchor (ot_kaddr()).
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#pragma once

#include <stdint.h>

/* IDT: 256 consecutive present interrupt/trap gates that all share one code
 * selector and whose handlers live in the kernel-text window. Returns the
 * kdata-relative offset of gate 0, or 0. */
uint64_t ot_find_idt(void);

/* TSS array: >= OT_TSS_MIN_ROWS consecutive `struct amd64tss` rows (stride
 * 0x68) whose rsp0 is a canonical kernel pointer. Returns the kdata-relative
 * offset of row 0, or 0. */
uint64_t ot_find_tss(void);

/* sysentvec: a struct whose sv_size is a plausible syscall count and whose
 * sv_table points at an array of sysent entries (stride 0x30) with small
 * n_arg values and kernel-text sy_call fields. Returns the kdata-relative
 * offset (0 if not found); writes the absolute sv_table pointer to *table_p and
 * sv_size to *sv_size. */
uint64_t ot_find_sysentvec(uint64_t *table_p, uint64_t *sv_size);

/* Narrow a sysentvec candidate set to the native (non-PS4) vector: the one
 * whose sv_size is largest. Helper for ot_find_sysentvec's callers. */

/* Largest run of zero bytes in the data region worth at least `min_len`. Used
 * as a code/data-cave hint (the cave is a zero sub-region, not a fixed
 * offset). Returns the kdata-relative offset and writes the run length to
 * *out_len (0/0 if none). */
uint64_t ot_find_cave(uint64_t *out_len);

/* Kernel pmap: scan for the pmap invariant (pm_pml4@+0x20, pm_cr3@+0x28,
 * page-aligned pm_pml4-pm_cr3) whose direct map actually resolves kdata back to
 * the same bytes. On success sets ot_pmap / ot_cr3 / ot_dmap and returns 0.
 * Returns <0 otherwise. Requires ot_kdata to be set. */
int ot_find_pmap(void);

/* Kernel text base: walk the (validated) kernel page tables down from kdata to
 * the base of the contiguous kernel-image mapping. Returns the absolute ktext
 * VA, or 0. Requires ot_cr3/ot_dmap (i.e. ot_find_pmap() to have succeeded). */
uint64_t ot_find_ktext(void);

/* SYS_GETUID: ktext-relative offset of the native getuid() handler, read from
 * sysentvec's sv_table (from ot_find_sysentvec) at the fixed syscall index.
 * 0 if unavailable. */
uint64_t ot_find_sys_getuid(uint64_t sv_table, uint64_t sv_size);

/* DMPML4I/DMPDPI: recover the two direct-map page-table indices from the
 * validated dmap, then locate their adjacent uint32 globals in kdata (next to
 * kernel_pmap_store). Writes *kdata-relative* offsets. Returns 0 on success. */
int ot_find_dmp(uint64_t *ml4i_off, uint64_t *pdpi_off);
