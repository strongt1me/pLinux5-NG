/*
 * kdlsym.c -- vendored and adapted from Byepervisor-Reborn (AGPL-3.0-or-later).
 *
 * Lookups prefer the firmware's Byepervisor table (source/offsets/byepervisor/)
 * when one exists, and otherwise fall back to pLinux5-NG's env_offset (the
 * linux offset_list, which carries the byepervisor fields for 13.20 via
 * off_1320). Gadgets/symbols resolve to absolute kernel text addresses via
 * ktext_addr(), and kdldmap() mirrors the kernel direct map.
 */
#include <stdio.h>
#include <ps5/kernel.h>

#include "byepervisor.h"
#include "kdlsym.h"
#include "utils.h"

uint64_t ktext_addr(uint64_t offset) { return ktext + offset; }

/* The Byepervisor table for the running firmware, or NULL if none is ported. */
static const bp_offsets *bp_cur(void) { return bp_get((uint16_t)fw); }

uint64_t kgadget(kgadget_t gadget) {
  if (gadget >= KERNEL_GADGET_MAX)
    return 0;

  const bp_offsets *bp = bp_cur();
  if (bp)
    return ktext_addr(bp->gadget[gadget]);

  switch (gadget) {
  case KERNEL_GADGET_PIVOT_ADD_RSP28_RET:
    return ktext_addr(env_offset.GAD_ADD_RSP_28_POP_RBP_RET);
  case KERNEL_GADGET_IRETQ:
    return ktext_addr(env_offset.GAD_IRETQ);
  case KERNEL_GADGET_POP_RAX:
    return ktext_addr(env_offset.GAD_POP_RAX_RET);
  case KERNEL_GADGET_POP_RCX:
    return ktext_addr(env_offset.GAD_POP_RCX_RET);
  case KERNEL_GADGET_POP_RDI:
    return ktext_addr(env_offset.GAD_POP_RDI_RET);
  case KERNEL_GADGET_POP_RSI:
    return ktext_addr(env_offset.GAD_POP_RSI_RET);
  case KERNEL_GADGET_POP_RDX:
    return ktext_addr(env_offset.GAD_POP_RDX_RET);
  case KERNEL_GADGET_POP_R8:
    return ktext_addr(env_offset.GAD_POP_R8);
  case KERNEL_GADGET_POP_RSP:
    return ktext_addr(env_offset.GAD_POP_RSP_RET);
  case KERNEL_GADGET_STORE_RCX_R8:
    return ktext_addr(env_offset.GAD_STORE_RCX_R8);
  case KERNEL_GADGET_STORE_RDI8_RCX:
    return ktext_addr(env_offset.GAD_STORE_RDI8_RCX);
  case KERNEL_GADGET_OR_RCX_EAX:
    return ktext_addr(env_offset.GAD_OR_RCX_EAX);
  case KERNEL_GADGET_SET_DR7:
    return ktext_addr(env_offset.GAD_SET_DR7);
  case KERNEL_GADGET_ST_RCX_RDX:
    return ktext_addr(env_offset.GAD_ST_RCX_RDX);
  case KERNEL_GADGET_ST_RCX_RAX:
    return ktext_addr(env_offset.GAD_ST_RCX_RAX);
  case KERNEL_GADGET_MOV_RAX_RSI:
    return ktext_addr(env_offset.GAD_MOV_RAX_RSI);
  case KERNEL_GADGET_MOV_RAX_RDI:
    return ktext_addr(env_offset.GAD_MOV_RAX_RDI);
  case KERNEL_GADGET_REP_MOVSB:
    return ktext_addr(env_offset.GAD_REP_MOVSB);
  case KERNEL_GADGET_CLD:
    return ktext_addr(env_offset.GAD_CLD);
  case KERNEL_GADGET_RET_TRAMP:
    return ktext_addr(env_offset.GAD_RET_TRAMP);
  case KERNEL_GADGET_DBREG_RESUME:
    return ktext_addr(env_offset.GAD_DBREG_RESUME);
  default:
    return 0;
  }
}

uint64_t kdlsym(ksym_t sym) {
  if (sym >= KERNEL_SYM_MAX)
    return 0;

  const bp_offsets *bp = bp_cur();
  if (bp) {
    /* HV symbols (HEAP_BASE/PCPUS) are hypervisor-image offsets, not kernel
     * text; every other symbol is ktext-relative. */
    if (sym >= HV_SYM_HEAP_BASE)
      return bp->sym[sym];
    return ktext_addr(bp->sym[sym]);
  }

  switch (sym) {
  case KERNEL_SYM_DMPML4I:
    return ktext_addr(env_offset.KERNEL_SYM_DMPML4I);
  case KERNEL_SYM_DMPDPI:
    return ktext_addr(env_offset.KERNEL_SYM_DMPDPI);
  case KERNEL_SYM_PML4PML4I:
    return ktext_addr(env_offset.KERNEL_SYM_PML4PML4I);
  case KERNEL_SYM_SYS_GETUID:
    return ktext_addr(env_offset.KERNEL_SYM_SYS_GETUID);
  case KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK:
    return ktext_addr(env_offset.HOOK_ACPI_WAKEUP_MACHDEP);
  case KERNEL_SYM_HV_MP_STARTUP_CALL:
    return ktext_addr(env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL);
  case KERNEL_SYM_MP_STARTUP_INIT_VECTOR:
    return ktext_addr(env_offset.KERNEL_SYM_MP_STARTUP_INIT_VECTOR);
  case KERNEL_SYM_PMAP_STORE:
    return ktext_addr(env_offset.KERNEL_SYM_PMAP_STORE);
  case KERNEL_SYM_DATA_CAVE:
    return ktext_addr(env_offset.KERNEL_SYM_DATA_CAVE);
  case KERNEL_SYM_IDT_ARRAY:
    return ktext_addr(env_offset.IDT);
  case KERNEL_SYM_COMMON_TSS:
    return ktext_addr(env_offset.COMMON_TSS);
  case HV_SYM_HEAP_BASE:
    return env_offset.HV_SYM_HEAP_BASE;
  case HV_SYM_PCPUS:
    return env_offset.HV_SYM_PCPUS;
  default:
    return 0;
  }
}

uint64_t rawoff(ksym_t sym) {
  if (sym >= KERNEL_SYM_MAX)
    return 0;

  const bp_offsets *bp = bp_cur();
  if (bp && sym >= HV_SYM_HEAP_BASE)
    return bp->sym[sym];

  switch (sym) {
  case HV_SYM_HEAP_BASE:
    return env_offset.HV_SYM_HEAP_BASE;
  case HV_SYM_PCPUS:
    return env_offset.HV_SYM_PCPUS;
  default:
    return kdlsym(sym) - ktext;
  }
}

uint64_t kdldmap(uint64_t pa) {
  uint32_t dmpml4i, dmpdpi;
  kread(kdlsym(KERNEL_SYM_DMPML4I), &dmpml4i, sizeof(dmpml4i));
  kread(kdlsym(KERNEL_SYM_DMPDPI), &dmpdpi, sizeof(dmpdpi));

  return (0xFFFF800000000000 | ((uint64_t)dmpml4i << 39) |
          ((uint64_t)dmpdpi << 30)) +
         pa;
}
