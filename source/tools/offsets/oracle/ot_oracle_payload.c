/*
 * ot_oracle_payload.c -- freestanding C half of the native #DB handler.
 *
 * Runs in kernel context on the IST stack after ot_oracle_entry has saved the
 * GPRs. It is a small state machine keyed on the control block mode plus an
 * entry counter:
 *
 *  record mode (stage A): record the interrupt frame + GPRs and return so the
 *      entry stub IRETQs straight back (TF cleared so the step does not recur).
 *
 *  step mode (stage B): on entry #1 (a user TF trap) stash the user context,
 *      then tell the stub to load a fully controlled register/stack/RIP state
 *      and jump to the candidate with TF set. The candidate executes exactly
 *      one instruction before the CPU raises #DB again; on entry #2 record the
 *      post-state, then tell the stub to restore the user context and IRETQ.
 */

#include "ot_oracle_layout.h"

static void copy15(uint64_t *dst, const uint64_t *src) {
  for (int i = 0; i < 15; i++)
    dst[i] = src[i];
}

int ot_oracle_c(struct ot_oracle_gregs *g, unsigned char *base) {
  uint64_t *frame = (uint64_t *)g + 15;
  struct ot_oracle_ctl *c = (struct ot_oracle_ctl *)(base + OT_ORACLE_PARAM_OFF);
  struct ot_oracle_result *r =
      (struct ot_oracle_result *)(base + OT_ORACLE_RESULT_OFF);
  uint64_t dr6;

  __asm__ volatile("mov %%dr6, %0" : "=r"(dr6));

  r->magic = OT_ORACLE_RESULT_MAGIC;
  r->entries += 1;

  if (c->mode == OT_MODE_STEP && r->entries == 1) {
    /* Stash the user context, then jump to the candidate. */
    c->saved_rip = frame[0];
    c->saved_cs = frame[1];
    c->saved_rflags = frame[2];
    c->saved_rsp = frame[3];
    c->saved_ss = frame[4];
    copy15((uint64_t *)&c->saved_gregs, (uint64_t *)g);
    return OT_ACT_STEP;
  }

  /* Record the post-state (stage A uses entry #1; stage B uses entry #2). */
  r->frame_rip = frame[0];
  r->frame_cs = frame[1];
  r->frame_rflags = frame[2];
  r->frame_rsp = frame[3];
  r->frame_ss = frame[4];
  copy15((uint64_t *)&r->gregs, (uint64_t *)g);
  r->dr6 = dr6;

  if (c->mode == OT_MODE_STEP)
    return OT_ACT_RET_USER;

  /* Clear TF (bit 8) so we do not single-step forever. */
  frame[2] &= ~0x100ULL;
  return OT_ACT_RETURN;
}
