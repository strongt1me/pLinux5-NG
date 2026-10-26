/*
 * ot_dump.h -- dump kernel .text + the HV loader region to a zip.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef OT_DUMP_H
#define OT_DUMP_H

/* Dump kernel .text ([ktext,kdata)) and the HV loader region (direct map of
 * the loader carveout) into a zip named after `fw_name`, written to the first
 * writable candidate path. Requires .text to be readable already (i.e. after a
 * successful ot_defeat()). Returns 0 on success, <0 otherwise. */
int ot_dump(const char *fw_name);

#endif /* OT_DUMP_H */
