/*
 * ot_oracle.h -- gadget-free execution oracle.
 *
 * Installs a native #DB (vector 1) handler (no kernel gadgets) into the data
 * cave, makes it executable, points IDT[1] at it with an IST stack, and drives
 * it from userland:
 *
 *   ot_oracle_selftest() -- stage A: single-step once to prove the handler is
 *       reached in kernel context and records the interrupt frame.
 *   ot_oracle_step(addr) -- stage B: single-step one instruction at `addr` with
 *       a controlled register/stack state, capturing the post-state. This
 *       validates a candidate gadget/instruction without reading kernel text.
 *
 * The gate/IST are always restored before returning.
 */
#ifndef OT_ORACLE_H
#define OT_ORACLE_H

#include <stdint.h>

int ot_oracle_selftest(void);
int ot_oracle_step(uint64_t addr);

#endif /* OT_ORACLE_H */
