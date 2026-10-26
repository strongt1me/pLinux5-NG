/*
 * Byepervisor vector offsets for firmware 11.60.
 *
 * Source: ps5-hv-bypass-porting firmwares/11.60.json (hardware-validated on a
 * regular-model console, 16 VMCBs changed/verified, kernel text readable after
 * resume).
 *
 * Chain adaptations on 11.60 (recorded in that manifest):
 *   - POP_R8 + STORE_RCX_R8  -> POP_RAX + ST_RCX_RAX
 *   - OR_RCX_EAX             -> unused by the one-shot path
 * so those three slots are left 0. HV_SYM_HEAP_BASE/PCPUS are also 0: 11.60
 * discovers the hypervisor structures at runtime instead of copying globals.
 *
 * Array order must match ksym_t / kgadget_t in include/byepervisor/kdlsym.h.
 */
#include "byepervisor.h"

static const uint64_t sym_1160[KERNEL_SYM_MAX] = {
    0x3B351B4, /* KERNEL_SYM_DMPML4I */
    0x3B351B8, /* KERNEL_SYM_DMPDPI */
    0x3B33D6C, /* KERNEL_SYM_PML4PML4I */
    0x34F590,  /* KERNEL_SYM_SYS_GETUID */
    0x535A50,  /* KERNEL_SYM_PRINTF */
    0x42FB40,  /* KERNEL_SYM_ACPI_SLEEP_MACHDEP_HOOK */
    0xC885D0,  /* KERNEL_SYM_HV_MP_STARTUP_CALL */
    0x3110B8,  /* KERNEL_SYM_MP_STARTUP_INIT_VECTOR */
    0x3B34F18, /* KERNEL_SYM_PMAP_STORE */
    0x2D02000, /* KERNEL_SYM_DATA_CAVE */
    0x3BA0300, /* KERNEL_SYM_IDT_ARRAY */
    0x3BA2FE0, /* KERNEL_SYM_COMMON_TSS */
    0,         /* HV_SYM_HEAP_BASE (runtime discovery) */
    0,         /* HV_SYM_PCPUS     (runtime discovery) */
};

static const uint64_t gadget_1160[KERNEL_GADGET_MAX] = {
    0x2A0EDE, /* KERNEL_GADGET_PIVOT_ADD_RSP28_RET */
    0x2AC22D, /* KERNEL_GADGET_IRETQ */
    0x338D2A, /* KERNEL_GADGET_POP_RAX */
    0x339712, /* KERNEL_GADGET_POP_RCX */
    0x289E0A, /* KERNEL_GADGET_POP_RDI */
    0x8AAFB5, /* KERNEL_GADGET_POP_RSI */
    0x3476DB, /* KERNEL_GADGET_POP_RDX */
    0,        /* KERNEL_GADGET_POP_R8      (replaced by POP_RAX) */
    0x33974D, /* KERNEL_GADGET_POP_RSP */
    0,        /* KERNEL_GADGET_STORE_RCX_R8 (replaced by ST_RCX_RAX) */
    0x3CC4AF, /* KERNEL_GADGET_STORE_RDI8_RCX */
    0,        /* KERNEL_GADGET_OR_RCX_EAX   (unused) */
    0xA7BD86, /* KERNEL_GADGET_SET_DR7 */
    0x8A2725, /* KERNEL_GADGET_ST_RCX_RDX */
    0x3620BF, /* KERNEL_GADGET_ST_RCX_RAX */
    0x958504, /* KERNEL_GADGET_MOV_RAX_RSI */
    0xC5E5DA, /* KERNEL_GADGET_MOV_RAX_RDI */
    0x304367, /* KERNEL_GADGET_REP_MOVSB */
    0x462C1A, /* KERNEL_GADGET_CLD */
    0x338D2B, /* KERNEL_GADGET_RET_TRAMP   (ret of pop rax @0x338D2A) */
    0x2A5778, /* KERNEL_GADGET_DBREG_RESUME */
};

const bp_offsets bp_1160 = {
    .fw = 0x1160,
    .name = "11.60",
    .source = "ps5-hv-bypass-porting firmwares/11.60.json (hardware-validated)",
    .kernel_text_base = 0,
    .production_ready = true,
    .sym = sym_1160,
    .gadget = gadget_1160,
};
