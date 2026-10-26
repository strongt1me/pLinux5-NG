/*
 * main.c -- standalone firmware-agnostic offsets tool.
 *
 * Phase 0: resolve the loader's kernel-data anchor, then DISCOVER the data-side
 * symbols (IDT, TSS, sysentvec, kernel pmap, ktext) from their own structural
 * invariants -- no per-firmware offset table is required. Nothing in kernel
 * .text is read, so this is safe while .text is still execute-only, on any
 * firmware 8.xx .. 13.xx.
 *
 * The discovered values are emitted as a `ktext`-relative fragment matching
 * offset_list, ready to drop into an off_XXXX.c.
 *
 * Later phases add: XOM defeat (nested-paging strike), then the text/HV dump.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "escape.h"
#include "ot_defeat.h"
#include "ot_dump.h"
#include "ot_env.h"
#include "ot_find.h"
#include "ot_harvest.h"
#include "ot_oracle.h"

#include "byepervisor/kdlsym.h"

#include <ps5/kernel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

struct disc {
  uint64_t idt; /* kdata-relative, 0 if not found */
  uint64_t tss; /* kdata-relative */
  uint64_t sysentvec;
  uint64_t sysents;
  uint64_t sv_size;
  uint64_t sv_table;   /* absolute */
  uint64_t sys_getuid; /* ktext-relative */
  uint64_t dmp_ml4i;   /* kdata-relative */
  uint64_t dmp_pdpi;   /* kdata-relative */
  uint64_t cave;       /* kdata-relative */
  uint64_t cave_len;
};

static void report(const struct disc *d) {
  printf("[ot] fw=0x%08x sel=0x%04x kdata=%#llx\n", ot_fw, ot_fwsel,
         (unsigned long long)ot_kdata);
  printf("[ot] ktext=%#llx K=%#llx\n", (unsigned long long)ot_ktext,
         (unsigned long long)(ot_kdata - ot_ktext));
  printf("[ot] pmap=%#llx (%#llx) cr3=%#llx dmap=%#llx\n",
         (unsigned long long)ot_pmap, (unsigned long long)(ot_pmap - ot_kdata),
         (unsigned long long)ot_cr3, (unsigned long long)ot_dmap);

  printf("[ot] discovery (kdata-relative):\n");
  printf("[ot]   %-14s %#llx\n", "idt", (unsigned long long)d->idt);
  printf("[ot]   %-14s %#llx\n", "tss_array", (unsigned long long)d->tss);
  printf("[ot]   %-14s %#llx\n", "sysentvec", (unsigned long long)d->sysentvec);
  if (d->sysentvec)
    printf("[ot]   sysents        %#llx (sv_size=%llu sv_table=%#llx)\n",
           (unsigned long long)d->sysents, (unsigned long long)d->sv_size,
           (unsigned long long)d->sv_table);
  if (d->sys_getuid)
    printf("[ot]   sys_getuid     %#llx (ktext-relative)\n",
           (unsigned long long)d->sys_getuid);
  if (d->dmp_ml4i)
    printf("[ot]   dmpml4i        %#llx (dmpdpi %#llx, kdata-relative)\n",
           (unsigned long long)d->dmp_ml4i, (unsigned long long)d->dmp_pdpi);
  printf("[ot]   %-14s %#llx\n", "pmap",
         (unsigned long long)(ot_pmap - ot_kdata));
  if (d->cave)
    printf("[ot]   cave hint      %#llx len=%#llx (largest zero run)\n",
           (unsigned long long)d->cave, (unsigned long long)d->cave_len);
}

/* Emit an offset_list fragment (ktext-relative, matching off_XXXX.c). Both
 * bases are discovered at runtime, so there is no per-firmware constant. */
static void emit(const struct disc *d) {
  if (!ot_ktext || ot_ktext >= ot_kdata) {
    printf("[ot] emit skipped: ktext underivable\n");
    return;
  }
  uint64_t K = ot_kdata - ot_ktext; /* kdata-relative -> ktext-relative shift */
  printf("[ot] emit (offset_list, ktext-relative):\n");
  printf("[ot]   /* K = kdata - text = %#llx */\n", (unsigned long long)K);
  if (d->idt)
    printf("[ot]   .IDT = %#llx,\n", (unsigned long long)(d->idt + K));
  if (d->tss)
    printf("[ot]   .COMMON_TSS = %#llx,\n", (unsigned long long)(d->tss + K));
  if (ot_pmap)
    printf("[ot]   .KERNEL_SYM_PMAP_STORE = %#llx,\n",
           (unsigned long long)((ot_pmap - ot_kdata) + K));
  if (d->sys_getuid)
    printf("[ot]   .KERNEL_SYM_SYS_GETUID = %#llx,\n",
           (unsigned long long)d->sys_getuid);
  if (d->dmp_ml4i)
    printf("[ot]   .KERNEL_SYM_DMPML4I = %#llx,\n",
           (unsigned long long)(d->dmp_ml4i + K));
  if (d->dmp_pdpi)
    printf("[ot]   .KERNEL_SYM_DMPDPI = %#llx,\n",
           (unsigned long long)(d->dmp_pdpi + K));
  if (d->cave)
    printf("[ot]   .KERNEL_SYM_DATA_CAVE = %#llx,\n",
           (unsigned long long)(d->cave + K));
}

/* Emit a source/offsets/byepervisor/bp_<fw>.c fragment. Only the data-side
 * symbols are discoverable before XOM is defeated, so the text/HV symbols and
 * every gadget stay 0 and the table is not production-ready. */
static void emit_bp(const struct disc *d) {
  if (!ot_ktext || ot_ktext >= ot_kdata) {
    printf("[ot] bp emit skipped: ktext underivable\n");
    return;
  }
  uint64_t K = ot_kdata - ot_ktext;
  uint64_t pmap = ot_pmap ? (ot_pmap - ot_kdata) + K : 0;
  uint64_t idt = d->idt ? d->idt + K : 0;
  uint64_t tss = d->tss ? d->tss + K : 0;
  uint64_t cave = d->cave ? d->cave + K : 0;
  uint64_t ml4i = d->dmp_ml4i ? d->dmp_ml4i + K : 0;
  uint64_t pdpi = d->dmp_pdpi ? d->dmp_pdpi + K : 0;

  static const char *names[] = {
      "KERNEL_SYM_DMPML4I",           "KERNEL_SYM_DMPDPI",
      "KERNEL_SYM_PML4PML4I",         "KERNEL_SYM_SYS_GETUID",
      "KERNEL_SYM_PRINTF",            "KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK",
      "KERNEL_SYM_HV_MP_STARTUP_CALL", "KERNEL_SYM_MP_STARTUP_INIT_VECTOR",
      "KERNEL_SYM_PMAP_STORE",        "KERNEL_SYM_DATA_CAVE",
      "KERNEL_SYM_IDT_ARRAY",         "KERNEL_SYM_COMMON_TSS",
      "HV_SYM_HEAP_BASE",             "HV_SYM_PCPUS",
  };
  const uint64_t vals[] = {
      ml4i,        pdpi, 0,          d->sys_getuid,
      0,           0,    0,          0,
      pmap,        cave, idt,        tss,
      0,           0,
  };

  printf("[ot] emit (byepervisor bp_%04x fragment, ktext-relative):\n", ot_fwsel);
  printf("[ot]   .fw = %#x,\n", ot_fwsel);
  printf("[ot]   .kernel_text_base = %#llxULL,\n", (unsigned long long)ot_ktext);
  printf("[ot]   .production_ready = false,\n");
  printf("[ot] static const uint64_t sym_%04x[KERNEL_SYM_MAX] = {\n", ot_fwsel);
  for (int i = 0; i < (int)(sizeof vals / sizeof vals[0]); i++)
    printf("[ot]     %#-12llx /* %s */\n", (unsigned long long)vals[i], names[i]);
  printf("[ot] };\n");
}

static void discover(struct disc *d) {
  d->idt = ot_find_idt();
  d->tss = ot_find_tss();
  d->sysentvec = ot_find_sysentvec(&d->sv_table, &d->sv_size);
  d->sysents = d->sv_table >= ot_kdata && d->sv_table < ot_kdata + 0x4000000
                   ? d->sv_table - ot_kdata
                   : 0;
  d->sys_getuid = ot_find_sys_getuid(d->sv_table, d->sv_size);
  if (ot_find_dmp(&d->dmp_ml4i, &d->dmp_pdpi) != 0)
    d->dmp_ml4i = d->dmp_pdpi = 0;
  d->cave = ot_find_cave(&d->cave_len);
}

/* Cross-check the page-table-derived ktext against the IDT: every interrupt
 * handler must be a kernel-text VA, i.e. inside [ktext, kdata). This catches a
 * page-table walk that stopped at a hole inside the image. */
static int ktext_sane(const struct disc *d) {
  if (!ot_ktext || ot_ktext >= ot_kdata || !d->idt)
    return 0;
  uint8_t idt[256 * 16];
  if (ot_rd(ot_kdata + d->idt, idt, sizeof idt) != 0)
    return 0;
  for (int i = 0; i < 256; i++) {
    const uint8_t *p = idt + i * 16;
    uint64_t h = ((uint64_t)rd32(p + 8) << 32) | ((uint64_t)rd16(p + 6) << 16) |
                 rd16(p);
    if (h < ot_ktext || h >= ot_kdata)
      return 0;
  }
  return 1;
}

static int have_marker(const char *name) {
  static const char *const dirs[] = {"/data", "/mnt/usb0", "/mnt/usb1",
                                     "/mnt/usb2", "/mnt/usb3", "/tmp", NULL};
  char path[128];
  for (int i = 0; dirs[i]; i++) {
    snprintf(path, sizeof path, "%s/%s", dirs[i], name);
    if (access(path, F_OK) == 0)
      return 1;
  }
  return 0;
}

/* Resolve a marker/reference file across the standard writable roots. */
static int find_path(const char *name, char *out, size_t n) {
  static const char *const dirs[] = {"/data", "/mnt/usb0", "/mnt/usb1",
                                     "/mnt/usb2", "/mnt/usb3", "/tmp", NULL};
  for (int i = 0; dirs[i]; i++) {
    snprintf(out, n, "%s/%s", dirs[i], name);
    if (access(out, F_OK) == 0)
      return 1;
  }
  return 0;
}

/* Optional stage-B target: a hex kernel VA read from pl5_offsets.target. */
static uint64_t read_target(void) {
  char path[128];
  if (!find_path("pl5_offsets.target", path, sizeof path))
    return 0;
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;
  unsigned long long v = 0;
  int ok = fscanf(f, "%llx", &v) == 1;
  fclose(f);
  return ok ? (uint64_t)v : 0;
}

/* Batch one-instruction validation: one hex kernel VA per line. */
static void run_candidates(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    printf("[ot] candidates: cannot open %s\n", path);
    return;
  }
  char line[128];
  int n = 0;
  while (fgets(line, sizeof line, f)) {
    unsigned long long v = 0;
    if (sscanf(line, "%llx", &v) != 1 || !v)
      continue;
    ot_oracle_step((uint64_t)v);
    n++;
  }
  fclose(f);
  printf("[ot] candidates: probed %d address(es)\n", n);
}

int main(int argc, char **argv) {
  int want_dump = 0;
  int want_oracle = 0;
  int want_step = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "dump"))
      want_dump = 1;
    if (!strcmp(argv[i], "oracle"))
      want_oracle = 1;
    if (!strcmp(argv[i], "step"))
      want_step = 1;
  }
  /* elfldr supplies no argv, so also accept marker files dropped via FTP/USB. */
  if (have_marker("pl5_offsets.dump"))
    want_dump = 1;
  if (have_marker("pl5_offsets.oracle"))
    want_oracle = 1;
  if (have_marker("pl5_offsets.step"))
    want_step = 1;

  printf("[ot] pl5 offsets tool (discovery%s%s%s)\n",
         want_dump ? " + dump" : "", want_oracle ? " + oracle" : "",
         want_step ? " + step" : "");
  fflush(stdout);

  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  int r = ot_bootstrap();
  if (r != 0) {
    printf("[ot] bootstrap failed: %d\n", r);
    fflush(stdout);
    return 1;
  }

  struct disc d = {0};
  discover(&d);
  report(&d);
  printf("[ot] ktext sane (IDT handlers in [ktext,kdata)): %s\n",
         ktext_sane(&d) ? "yes" : "no");
  emit(&d);
  emit_bp(&d);

  struct ot_harvest hv;
  ot_harvest_run(d.sv_table, d.sv_size, d.idt, &hv);
  printf("[ot] harvest: syscalls=%llu idt=%llu sweep=%llu tables=%llu "
         "max=%llu@%#llx\n",
         (unsigned long long)hv.sys_calls, (unsigned long long)hv.idt_handlers,
         (unsigned long long)hv.sweep_ptrs, (unsigned long long)hv.tables,
         (unsigned long long)hv.table_max, (unsigned long long)hv.table_max_off);
  printf("[ot] harvest: text range [%#llx,%#llx] gap=%#llx ktext_ok=%d\n",
         (unsigned long long)hv.ptr_min, (unsigned long long)hv.ptr_max,
         (unsigned long long)hv.ktext_gap, hv.ktext_ok);

  if (want_oracle) {
    ot_env_sync();
    ot_oracle_selftest();
  }

  if (want_step) {
    ot_env_sync();
    char cpath[128];
    if (find_path("pl5_offsets.candidates", cpath, sizeof cpath)) {
      run_candidates(cpath);
    } else {
      uint64_t target = read_target();
      if (!target) {
        target = kdlsym(KERNEL_SYM_SYS_GETUID);
        printf("[ot] step: no target/candidates; using SYS_GETUID %#lx\n",
               (unsigned long)target);
      }
      ot_oracle_step(target);
    }
  }

  if (want_dump) {
    char fwname[16];
    snprintf(fwname, sizeof fwname, "%02x.%02x", (ot_fwsel >> 8) & 0xff,
             ot_fwsel & 0xff);

    ot_env_sync();
    if (!ot_defeat_supported()) {
      printf("[ot] dump: no byepervisor table for this fw; cannot escape.\n");
    } else if (ot_defeat() == 0) {
      ot_dump(fwname);
    } else {
      printf("[ot] dump: defeat failed; skipping.\n");
    }
  }

  printf("[ot] done\n");
  fflush(stdout);
  return 0;
}
