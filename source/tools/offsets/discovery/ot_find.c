/*
 * ot_find.c -- data-only symbol discovery for the offsets tool.
 * See ot_find.h.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "ot_find.h"

#include "escape.h"

#include <stdint.h>
#include <string.h>

/* Scan cap: every data symbol we discover lives in the first ~50 MiB of kdata.
 * ocpmap/idt/tss/sysentvec/caves are all well inside this on 8.xx..13.xx. */
#define OT_SCAN_MAX 0x4000000ULL
#define OT_WIN 0x100000ULL /* 1 MiB window */
#define OT_OVL 0x2000ULL    /* overlap so a pattern can straddle a boundary */
#define OT_WIN_BUF (OT_WIN + OT_OVL)

#define PTE_P 0x1ULL
#define PTE_PS 0x80ULL
#define PTE_NX (1ULL << 63)
#define PA_MASK 0x000FFFFFFFFFF000ULL

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

/* Read one scan window [base, base+OT_WIN_BUF) into g_win. Returns bytes read
 * (0 on failure). Failure is expected past the end of the data region. */
static size_t rd_win(uint64_t base) {
  if (ot_rd(ot_kdata + base, g_win, OT_WIN_BUF) != 0)
    return 0;
  return OT_WIN_BUF;
}

/* --------------------------------------------------------------- IDT ----- */
static int gate_at(const uint8_t *p, uint16_t *sel) {
  uint16_t typ = rd16(p + 4);
  if (!(typ & 0x8000))
    return 0;
  int t = (typ >> 8) & 0xf;
  if (t != 0xe && t != 0xf)
    return 0;
  uint64_t off =
      ((uint64_t)rd32(p + 8) << 32) | ((uint64_t)rd16(p + 6) << 16) | rd16(p);
  /* Handler must be a kernel-image VA. The image base is firmware-specific
   * (e.g. 0xffffffff8a... on 13.60 but 0xffffffffd3... on 13.20), so only the
   * top-of-canonical test is valid. */
  if (off < 0xffffffff80000000ULL)
    return 0;
  *sel = rd16(p + 2);
  return 1;
}

uint64_t ot_find_idt(void) {
  uint64_t best = 0;
  size_t best_len = 0;
  for (uint64_t base = 0; base < OT_SCAN_MAX; base += OT_WIN) {
    if (!rd_win(base))
      continue;
    size_t got = OT_WIN_BUF;
    for (size_t i = 0; i + 16 <= got; i += 8) {
      uint16_t sel;
      if (!gate_at(g_win + i, &sel))
        continue;
      size_t c = 1;
      while (i + (c + 1) * 16 <= got) {
        uint16_t s;
        if (!gate_at(g_win + i + c * 16, &s) || s != sel)
          break;
        c++;
      }
      /* The IDT is exactly 256 gates; coincidental longer chains exist in
       * pointer-dense data, so take the shortest run that can be the IDT. */
      if (c >= 256 && (best == 0 || c < best_len)) {
        best = base + i;
        best_len = c;
      }
      i += c * 16 - 8;
    }
  }
  return best;
}

/* --------------------------------------------------------------- TSS ----- */
/* struct amd64tss: rsp0 @0x04, ist[1] @0x24 (stride 0x68). Both are kernel
 * stack pointers, so requiring both to be canonical rejects the strings/ints
 * that fill most of the data region. */
static int tss_row(const uint8_t *p) {
  uint64_t rsp0 = rd64(p + 4);
  uint64_t ist1 = rd64(p + 0x24);
  return rsp0 > 0xffff000000000000ULL && ist1 > 0xffff000000000000ULL;
}

uint64_t ot_find_tss(void) {
  uint64_t best = 0, best_len = 0;
  for (uint64_t base = 0; base < OT_SCAN_MAX; base += OT_WIN) {
    if (!rd_win(base))
      continue;
    size_t got = OT_WIN_BUF;
    for (size_t i = 0; i + 0x68 <= got; i += 8) {
      if (!tss_row(g_win + i))
        continue;
      size_t c = 1;
      while (i + (c + 1) * 0x68 <= got && tss_row(g_win + i + c * 0x68))
        c++;
      /* The real array is a handful of CPUs' worth of rows; longer runs are
       * coincidental chains through other pointer-dense data. */
      if (c >= 8 && c <= 16 && c > best_len) {
        best_len = c;
        best = base + i;
      }
      i += c * 0x68 - 8;
    }
  }
  return best;
}

/* ---------------------------------------------------------- sysentvec ---- */
/* struct sysent { u32 n_arg; u32 pad; u64 sy_call; ... } stride 0x30. */
#define SYSENT_STRIDE 0x30
#define SYSENT_SY_CALL 0x8
#define SYSENT_CHECK 64

/* getuid() syscall index in the native (PS5/FreeBSD) sysent table. */
#define SYS_GETUID_NUM 24

static int sy_call_text(uint64_t v) {
  return v >= 0xffffffff80000000ULL;
}

/* Confirm a candidate by reading its table: the entries must look like real
 * sysent records. This is what separates the sysentvec from the many other
 * structs whose +0x28/+0x30 happen to hold text pointers. Works on console for
 * tables that live in the kernel image *or* behind a direct-map alias. */
static int table_ok(uint64_t tbl) {
  static uint8_t tab[SYSENT_CHECK * SYSENT_STRIDE];
  if (tbl < 0xffff000000000000ULL)
    return 0;
  if (ot_rd(tbl, tab, sizeof tab) != 0)
    return 0;
  for (int k = 0; k < SYSENT_CHECK; k++) {
    uint32_t n_arg = rd32(tab + k * SYSENT_STRIDE);
    uint64_t call = rd64(tab + k * SYSENT_STRIDE + SYSENT_SY_CALL);
    if (n_arg >= 20 || !sy_call_text(call))
      return 0;
  }
  return 1;
}

uint64_t ot_find_sysentvec(uint64_t *table_p, uint64_t *sv_size) {
  uint64_t best = 0, best_sz = 0, best_tbl = 0;

  for (uint64_t base = 0; base < OT_SCAN_MAX; base += OT_WIN) {
    if (!rd_win(base))
      continue;
    size_t got = OT_WIN_BUF;
    for (size_t i = 0; i + 0x50 <= got; i += 8) {
      uint64_t rel = base + i;
      uint32_t sz = rd32(g_win + i);
      uint64_t tbl = rd64(g_win + i + 8);
      if (sz < 400 || sz > 900)
        continue;
      /* sv_size is followed by two more text pointers in every sysentvec. */
      if (!sy_call_text(rd64(g_win + i + 0x28)) ||
          !sy_call_text(rd64(g_win + i + 0x30)))
        continue;
      if (!table_ok(tbl))
        continue;
      /* Native vector has the most syscalls; tie-break on the lowest address
       * (its ps4 twin and any alias copy sit higher). */
      if (sz > best_sz || (sz == best_sz && (best == 0 || rel < best))) {
        best_sz = sz;
        best = rel;
        best_tbl = tbl;
      }
    }
  }
  if (table_p)
    *table_p = best_tbl;
  if (sv_size)
    *sv_size = best_sz;
  return best;
}

/* SYS_GETUID: the native sysent entry's sy_call is the getuid() handler, a
 * kernel-text address. Return its ktext-relative offset (0 if unavailable).
 * Requires the sysentvec's sv_table (from ot_find_sysentvec) and ot_ktext. */
uint64_t ot_find_sys_getuid(uint64_t sv_table, uint64_t sv_size) {
  if (!sv_table || !ot_ktext || sv_size <= SYS_GETUID_NUM)
    return 0;
  uint64_t call = 0;
  if (ot_rd(sv_table + (uint64_t)SYS_GETUID_NUM * SYSENT_STRIDE + SYSENT_SY_CALL,
            &call, 8) != 0)
    return 0;
  if (!sy_call_text(call) || call < ot_ktext)
    return 0;
  return call - ot_ktext;
}

/* --------------------------------------------------------------- cave ---- */
/* A staging cave is a zero sub-region, validated at runtime (write/readback,
 * permissions, persistence). Offline we can only propose candidates, so return
 * the largest zero run in the data region with no position preference. */
uint64_t ot_find_cave(uint64_t *out_len) {
  uint64_t best = 0, best_len = 0, run = 0, run_off = 0;
  const uint64_t MIN = 0x10000;

  for (uint64_t base = 0; base < OT_SCAN_MAX; base += OT_WIN) {
    if (!rd_win(base))
      continue;
    size_t got = OT_WIN_BUF;
    for (size_t i = 0; i < got; i++) {
      if (g_win[i] == 0) {
        if (run == 0)
          run_off = base + i;
        run++;
        if (run > best_len) {
          best_len = run;
          best = run_off;
        }
      } else {
        run = 0;
      }
    }
  }
  if (best_len < MIN)
    best = best_len = 0;
  if (out_len)
    *out_len = best_len;
  return best;
}

/* --------------------------------------------------------------- pmap ---- */
/* The leaf PTE for `va` under (cr3,dmap), via the direct map. 0 if absent. */
static uint64_t leaf_for(uint64_t va, uint64_t cr3, uint64_t dmap) {
  uint64_t tbl = cr3 & PA_MASK;
  for (int lvl = 0; lvl < 4; lvl++) {
    uint64_t idx = (va >> (39 - lvl * 9)) & 0x1ff;
    uint64_t e = 0;
    if (ot_rd(dmap + tbl + idx * 8, &e, 8) != 0)
      return 0;
    if (!(e & PTE_P))
      return 0;
    if ((lvl == 1 || lvl == 2) && (e & PTE_PS))
      return e;
    if (lvl == 3)
      return e;
    tbl = e & PA_MASK;
  }
  return 0;
}

/* Validate (cr3,dmap): the direct map must resolve `va` back to the same bytes
 * we can already read from the kernel image. Two independent paths agree.
 * Handles 1 GiB / 2 MiB pages (the offset within the page is wider than 12
 * bits), which is what the kernel image is mapped with. */
static int dmap_valid(uint64_t va, uint64_t cr3, uint64_t dmap) {
  uint64_t tbl = cr3 & PA_MASK;
  for (int lvl = 0; lvl < 4; lvl++) {
    uint64_t idx = (va >> (39 - lvl * 9)) & 0x1ff;
    uint64_t e;
    if (ot_rd(dmap + tbl + idx * 8, &e, 8) != 0)
      return 0;
    if (!(e & PTE_P))
      return 0;

    uint64_t pa;
    if ((lvl == 1 || lvl == 2) && (e & PTE_PS)) {
      uint64_t pg = (lvl == 1) ? (1ULL << 30) : (1ULL << 21);
      pa = (e & PA_MASK) | (va & (pg - 1));
    } else if (lvl == 3) {
      pa = (e & PA_MASK) | (va & 0xfff);
    } else {
      tbl = e & PA_MASK;
      continue;
    }

    uint64_t via_dmap = 0, direct = 0;
    if (ot_rd(dmap + pa, &via_dmap, 8) != 0)
      return 0;
    if (ot_rd(va, &direct, 8) != 0)
      return 0;
    return via_dmap == direct;
  }
  return 0;
}

struct cand {
  uint64_t off, pml4, cr3, dmap;
};

int ot_find_pmap(void) {
  enum { MAXC = 64 };
  static struct cand cands[MAXC];
  static uint64_t dmap_best[32];
  static uint32_t dmap_cnt[32];
  size_t nc = 0, nd = 0;

  for (uint64_t base = 0; base < OT_SCAN_MAX && nc < MAXC; base += OT_WIN) {
    if (!rd_win(base))
      continue;
    size_t got = OT_WIN_BUF;
    for (size_t i = 0; i + 0x30 <= got && nc < MAXC; i += 8) {
      uint64_t pml4 = rd64(g_win + i + 0x20);
      uint64_t cr3 = rd64(g_win + i + 0x28);
      /* pm_cr3 is the physical address of the top-level page table, so it is
       * page-aligned and lives low in RAM. Reject the sentinel-shaped
       * (0xffffffff00000000, 0x100000000) coincidences seen in both 13.20 and
       * 13.60 dumps before they reach the expensive validation. */
      if (cr3 == 0 || (cr3 & 0xfff) || cr3 > 0x80000000ULL)
        continue;
      if (pml4 < 0xffff000000000000ULL)
        continue;
      uint64_t d = pml4 - cr3;
      if (d & 0x3fffffffULL)
        continue;
      cands[nc].off = base + i;
      cands[nc].pml4 = pml4;
      cands[nc].cr3 = cr3;
      cands[nc].dmap = d;
      nc++;
      for (size_t j = 0; j < nd; j++)
        if (dmap_best[j] == d) {
          dmap_cnt[j]++;
          goto counted;
        }
      if (nd < 32) {
        dmap_best[nd] = d;
        dmap_cnt[nd] = 1;
        nd++;
      }
    counted:;
    }
  }

  /* Try the dmaps in descending support order; accept the first that actually
   * round-trips a kernel-data byte through the direct map. */
  for (int pass = 0; pass < (int)nd; pass++) {
    int bi = -1;
    uint32_t bc = 0;
    for (size_t j = 0; j < nd; j++)
      if (dmap_cnt[j] > bc) {
        bc = dmap_cnt[j];
        bi = (int)j;
      }
    if (bi < 0)
      break;
    uint64_t d = dmap_best[bi];
    dmap_cnt[bi] = 0;

    uint64_t idt = ot_find_idt();
    uint64_t probe = ot_kdata + (idt ? idt : 0);
    /* Find a candidate with this dmap whose (cr3,dmap) validates. */
    uint64_t good_cr3 = 0;
    for (size_t k = 0; k < nc; k++) {
      if (cands[k].dmap != d)
        continue;
      if (dmap_valid(probe, cands[k].cr3, d)) {
        good_cr3 = cands[k].cr3;
        break;
      }
    }
    if (good_cr3) {
      /* Several static `struct pmap`s in kdata share the kernel cr3/pml4. The
       * one the payload names kernel_pmap_store is the last such struct in the
       * image, so take the highest offset that shares the validated cr3. */
      uint64_t best_off = 0;
      for (size_t k = 0; k < nc; k++)
        if (cands[k].dmap == d && cands[k].cr3 == good_cr3 &&
            cands[k].off > best_off)
          best_off = cands[k].off;
      ot_pmap = ot_kdata + best_off;
      ot_cr3 = good_cr3;
      ot_dmap = d;
      return 0;
    }
  }
  return -1;
}

/* -------------------------------------------------------------- ktext ---- */
/* The kernel image is mapped as one contiguous virtual range: executable text
 * at the bottom, then rodata/data (kdata_base sits inside it). Walking down
 * from kdata one page at a time reaches the image base at the first unmapped
 * page; that base is ktext. No per-firmware constant and no .text read -- the
 * mappings come from the pmap we already validated. Requires ot_cr3/ot_dmap. */
uint64_t ot_find_ktext(void) {
  if (!ot_cr3 || !ot_dmap || !ot_kdata)
    return 0;

  const uint64_t LIMIT = 0x2000000ULL; /* image text+rodata < 32 MiB */
  uint64_t start = ot_kdata & ~0xfffULL;
  uint64_t va = start;
  uint64_t floor = ot_kdata > LIMIT ? ot_kdata - LIMIT : 0;
  uint64_t low_exec = 0;

  for (; va >= floor; va -= 0x1000) {
    uint64_t e = leaf_for(va, ot_cr3, ot_dmap);
    if (!(e & PTE_P))
      break;
    if (!(e & PTE_NX))
      low_exec = va;
    if (va == 0)
      break;
  }

  /* The image base is the bottom of the executable text run; the mapping just
   * below it may be a separate (non-executable) region. */
  if (!low_exec || low_exec >= start)
    return 0;
  return low_exec;
}

/* ------------------------------------------------------ DMPML4I/DMPDPI ---- */
/* The direct map is built as 0xFFFF800000000000 | (DMPML4I<<39) |
 * (DMPDPI<<30). We already know the dmap from the validated pmap, so recover
 * the two indices, then find the adjacent u32 pair in kdata that holds them.
 * Both are uint32 globals sitting next to kernel_pmap_store. Returns 0 and
 * writes the *kdata-relative* offsets on success, <0 otherwise. */
int ot_find_dmp(uint64_t *ml4i_off, uint64_t *pdpi_off) {
  if (!ot_pmap || !ot_dmap)
    return -1;

  uint64_t base = ot_dmap - 0xFFFF800000000000ULL;
  uint32_t idx4 = (uint32_t)((base >> 39) & 0x1ff);
  uint32_t idxd = (uint32_t)((base >> 30) & 0x1ff);
  if (idx4 == 0 && idxd == 0)
    return -1;

  uint64_t pmap_off = ot_pmap - ot_kdata;
  uint64_t lo = pmap_off > 0x4000 ? pmap_off - 0x4000 : 0;
  uint64_t hi = pmap_off + 0x4000;
  static uint8_t buf[0x8000];
  size_t len = (size_t)(hi - lo);
  if (len > sizeof buf)
    len = sizeof buf;
  if (ot_rd(ot_kdata + lo, buf, len) != 0)
    return -1;

  for (size_t i = 0; i + 8 <= len; i += 4) {
    if (rd32(buf + i) == idx4 && rd32(buf + i + 4) == idxd) {
      if (ml4i_off)
        *ml4i_off = lo + i;
      if (pdpi_off)
        *pdpi_off = lo + i + 4;
      return 0;
    }
  }
  return -1;
}
