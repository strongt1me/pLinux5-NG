/*
 * Byepervisor vector offsets for firmware 12.20 (research in progress).
 *
 * Source: ps5-hv-bypass-porting firmwares/12.20.json. Not production ready:
 * several symbols are unknown and the store/copy gadgets are still only
 * "candidate" (prepared-safe-probe, never executed live):
 *   REP_MOVSB, CLD, ST_RCX_RAX, ST_RCX_RDX, STORE_RDI8_RCX.
 *
 * Array order must match ksym_t / kgadget_t in include/byepervisor/kdlsym.h.
 */
#include "byepervisor.h"

static const uint64_t sym_1220[KERNEL_SYM_MAX] = {
    0x3B6D254, /* KERNEL_SYM_DMPML4I */
    0x3B6D258, /* KERNEL_SYM_DMPDPI */
    0x3B6BE0C, /* KERNEL_SYM_PML4PML4I */
    0,         /* KERNEL_SYM_SYS_GETUID  (unknown) */
    0,         /* KERNEL_SYM_PRINTF      (unknown) */
    0,         /* KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK (unknown) */
    0,         /* KERNEL_SYM_HV_MP_STARTUP_CALL      (unknown) */
    0,         /* KERNEL_SYM_MP_STARTUP_INIT_VECTOR  (unknown) */
    0x3B6CFB8, /* KERNEL_SYM_PMAP_STORE */
    0x2D23000, /* KERNEL_SYM_DATA_CAVE */
    0x3BD8300, /* KERNEL_SYM_IDT_ARRAY */
    0x3BDAFE0, /* KERNEL_SYM_COMMON_TSS */
    0,         /* HV_SYM_HEAP_BASE (unknown) */
    0,         /* HV_SYM_PCPUS     (unknown) */
};

static const uint64_t gadget_1220[KERNEL_GADGET_MAX] = {
    0x2A815E, /* KERNEL_GADGET_PIVOT_ADD_RSP28_RET */
    0x2B34AD, /* KERNEL_GADGET_IRETQ */
    0,        /* KERNEL_GADGET_POP_RAX      (unknown) */
    0x3410D2, /* KERNEL_GADGET_POP_RCX */
    0x2A6784, /* KERNEL_GADGET_POP_RDI */
    0x2F5CB0, /* KERNEL_GADGET_POP_RSI */
    0x34F4EB, /* KERNEL_GADGET_POP_RDX */
    0,        /* KERNEL_GADGET_POP_R8       (unknown) */
    0,        /* KERNEL_GADGET_POP_RSP      (unknown) */
    0,        /* KERNEL_GADGET_STORE_RCX_R8 (unknown) */
    0x3D66DF, /* KERNEL_GADGET_STORE_RDI8_RCX  (candidate) */
    0x899E20, /* KERNEL_GADGET_OR_RCX_EAX */
    0,        /* KERNEL_GADGET_SET_DR7      (unknown) */
    0x8BBA75, /* KERNEL_GADGET_ST_RCX_RDX      (candidate) */
    0x369DEF, /* KERNEL_GADGET_ST_RCX_RAX      (candidate) */
    0x971E64, /* KERNEL_GADGET_MOV_RAX_RSI */
    0,        /* KERNEL_GADGET_MOV_RAX_RDI  (rejected: semantics mismatch) */
    0x30B6C7, /* KERNEL_GADGET_REP_MOVSB       (candidate) */
    0x369460, /* KERNEL_GADGET_CLD             (candidate) */
    0,        /* KERNEL_GADGET_RET_TRAMP    (unknown) */
    0,        /* KERNEL_GADGET_DBREG_RESUME (unknown) */
};

const bp_offsets bp_1220 = {
    .fw = 0x1220,
    .name = "12.20",
    .source = "ps5-hv-bypass-porting firmwares/12.20.json (research in progress)",
    .kernel_text_base = 0,
    .production_ready = false,
    .sym = sym_1220,
    .gadget = gadget_1220,
};
