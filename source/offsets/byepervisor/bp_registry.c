/*
 * Byepervisor vector offset registry.
 *
 * Maps a firmware selector (kernel_get_fw_version() >> 16, e.g. 0x1320) to its
 * bp_offsets table. Firmwares without a table (e.g. 09.60, not ported yet)
 * return NULL so the caller can fall back to runtime discovery.
 */
#include "byepervisor.h"

const bp_offsets *bp_get(uint16_t fw) {
  switch (fw) {
  case 0x1160:
    return &bp_1160;
  case 0x1220:
    return &bp_1220;
  case 0x1300:
    return &bp_1300;
  case 0x1320:
    return &bp_1320;
  case 0x1360:
    return &bp_1360;
  default:
    return 0;
  }
}
