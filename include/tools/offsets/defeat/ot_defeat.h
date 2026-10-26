/*
 * ot_defeat.h -- XOM defeat for the offsets tool.
 *
 * Ports the Byepervisor khook escape (as used by pLinux5-NG's 8.xx+ vector)
 * into the standalone tool, minus the Linux-boot takeover: escape the guest
 * page tables, install the S3-resume hook that runs break_hv (which disables
 * nested paging on every core), then wait for the resume cookie. Once NPT is
 * off the kernel .text is readable and can be dumped.
 *
 * Arming needs per-firmware text/gadget offsets, so it only works for a
 * firmware covered by a Byepervisor table (source/offsets/byepervisor/).
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef OT_DEFEAT_H
#define OT_DEFEAT_H

/* Non-zero when the running firmware has the text/gadget offsets the escape
 * needs (i.e. bp_get() found a table). */
int ot_defeat_supported(void);

/* Escape the guest, arm the resume hook, enter rest mode and wait for the
 * console to resume with NPT disabled. Returns 0 once .text is readable, <0
 * otherwise. Blocks until the user wakes the console. */
int ot_defeat(void);

#endif /* OT_DEFEAT_H */
