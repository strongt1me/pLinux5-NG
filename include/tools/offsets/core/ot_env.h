/*
 * ot_env.h -- compatibility layer between the offsets tool's discovered anchors
 * and the vendored Byepervisor modules (kdlsym/paging/khook).
 *
 * The vendored modules were written against pLinux5-NG's globals (ktext, kdata,
 * dmap, cr3, fw, env_offset) and userland helpers (notify, pin_to_core, ...).
 * ot_env.c defines those here so the same code can be linked into the
 * standalone offsets tool, sourcing the globals from ot_* (escape.c/ot_find.c).
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef OT_ENV_H
#define OT_ENV_H

/* Copy the discovered anchors (ot_ktext/ot_kdata/ot_dmap/ot_cr3/ot_fwsel) into
 * the globals the vendored modules read. Call after ot_bootstrap(). */
void ot_env_sync(void);

#endif /* OT_ENV_H */
