#ifndef OFFSETS_BYEPERVISOR_H
#define OFFSETS_BYEPERVISOR_H

#include <stdint.h>
#include <stdbool.h>

#include "kdlsym.h" /* ksym_t, kgadget_t, KERNEL_SYM_MAX, KERNEL_GADGET_MAX */

/*
 * Byepervisor vector offsets (the high-firmware HV bypass, 8.xx-13.60).
 *
 * Kept separate from offset_list (the offsets pLinux5-NG itself uses, in
 * source/offsets/linux/). Values are ktext-relative -- add the runtime
 * kernel text base -- matching Byepervisor-Reborn's per-firmware sym and
 * gadget maps. A value of 0 means "unknown for this firmware".
 *
 * Provenance:
 *   13.00 / 13.20 / 13.60 : Byepervisor-Reborn include/offsets headers
 *   11.60 / 12.20         : ps5-hv-bypass-porting JSON manifests
 *                           (11.60 hardware-validated, 12.20 partial).
 *   09.60                 : not ported yet.
 */
typedef struct {
  uint16_t fw;                /* firmware selector, e.g. 0x1320 */
  const char *name;           /* "13.20" */
  const char *source;         /* provenance note */
  uint64_t kernel_text_base;  /* informational KERNEL_ADDRESS_TEXT_BASE, 0 = unknown */
  bool production_ready;      /* every required sym/gadget validated */
  const uint64_t *sym;        /* [KERNEL_SYM_MAX], ktext-relative */
  const uint64_t *gadget;     /* [KERNEL_GADGET_MAX], ktext-relative */
} bp_offsets;

/* One table per firmware that has been ported. */
extern const bp_offsets bp_1160;
extern const bp_offsets bp_1220;
extern const bp_offsets bp_1300;
extern const bp_offsets bp_1320;
extern const bp_offsets bp_1360;

/* Look up by firmware selector (as returned by kernel_get_fw_version() >> 16).
 * Returns NULL when this firmware has no Byepervisor table yet. */
const bp_offsets *bp_get(uint16_t fw);

#endif /* OFFSETS_BYEPERVISOR_H */
