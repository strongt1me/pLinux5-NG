/*
 * ot_dump.c -- kernel .text + HV loader dump for the offsets tool.
 *
 * After ot_defeat() the guest can read kernel .text, so we stream [ktext,kdata)
 * and the HV loader carveout (via the direct map) into a zip. Reads are
 * page-bounded and stop at the first fault so an unmapped HV tail cannot wedge
 * the console.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "ot_dump.h"

#include "escape.h"
#include "miniz.h"

#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* HV-loader carveout base (regular/retail). */
#define HV_LOADER_PA_REGULAR 0x062800000ULL
/* Upper bound on how much of the HV region to attempt; a fault stops the copy
 * early, so an over-estimate only costs a couple of failed page reads. */
#define OT_HV_MAX 0x1000000ULL

static const char *const g_out_dirs[] = {
    "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3", "/data", "/tmp", NULL,
};

/* Page-bounded kernel copyout that stops at the first page the kernel cannot
 * read. Returns the number of bytes actually copied. */
static size_t safe_read(uint64_t va, uint8_t *dst, size_t len) {
  size_t done = 0;
  while (done + 0x1000 <= len) {
    if (kernel_copyout((intptr_t)(va + done), dst + done, 0x1000) != 0)
      break;
    done += 0x1000;
  }
  return done;
}

int ot_dump(const char *fw_name) {
  if (!ot_ktext || ot_kdata <= ot_ktext) {
    printf("[ot] dump: ktext/kdata unavailable\n");
    return -1;
  }

  size_t text_len = (size_t)(ot_kdata - ot_ktext);
  uint8_t *text = malloc(text_len);
  if (!text) {
    printf("[ot] dump: out of memory for .text (%zu bytes)\n", text_len);
    return -1;
  }
  size_t got = safe_read(ot_ktext, text, text_len);
  printf("[ot] dump: .text %zu/%zu bytes read\n", got, text_len);
  if (got < 0x1000) {
    printf("[ot] dump: .text not readable; run the defeat first\n");
    free(text);
    return -1;
  }

  size_t hv_max = OT_HV_MAX;
  uint8_t *hv = malloc(hv_max);
  if (!hv) {
    printf("[ot] dump: out of memory for HV (%zu bytes)\n", hv_max);
    free(text);
    return -1;
  }
  size_t hv_got = safe_read(ot_dmap + HV_LOADER_PA_REGULAR, hv, hv_max);
  printf("[ot] dump: HV %zu bytes read @ dmap+%#llx\n", hv_got,
         (unsigned long long)HV_LOADER_PA_REGULAR);

  char name[96], path[160];
  snprintf(name, sizeof name, "pl5_offsets_%s.zip", fw_name ? fw_name : "fw");

  mz_zip_archive zip;
  mz_zip_zero_struct(&zip);
  const char *used = NULL;
  for (int i = 0; g_out_dirs[i]; i++) {
    snprintf(path, sizeof path, "%s/%s", g_out_dirs[i], name);
    if (mz_zip_writer_init_file(&zip, path, 0)) {
      used = g_out_dirs[i];
      break;
    }
    mz_zip_zero_struct(&zip);
  }
  if (!used) {
    printf("[ot] dump: no writable output path (tried /mnt/usb*, /data, /tmp)\n");
    free(text);
    free(hv);
    return -1;
  }

  mz_bool ok = mz_zip_writer_add_mem(&zip, "kernel_text.bin", text, got,
                                     MZ_DEFAULT_COMPRESSION);
  if (hv_got)
    ok = mz_zip_writer_add_mem(&zip, "hv_loader.bin", hv, hv_got,
                               MZ_DEFAULT_COMPRESSION) && ok;
  ok = mz_zip_writer_finalize_archive(&zip) && ok;
  mz_zip_writer_end(&zip);

  printf("[ot] dump: wrote %s (%s)\n", path, ok ? "ok" : "partially");
  free(text);
  free(hv);
  return ok ? 0 : -1;
}
