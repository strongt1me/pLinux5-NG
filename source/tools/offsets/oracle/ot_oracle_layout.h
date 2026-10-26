#ifndef OT_ORACLE_LAYOUT_H
#define OT_ORACLE_LAYOUT_H

/*
 * Layout shared between the freestanding #DB handler blob
 * (oracle/ot_oracle_payload.c + oracle/ot_oracle_entry.S) and the outer
 * installer (ot_oracle.c).
 *
 * The blob is linked at VA 0 and copied verbatim into the kernel data cave at
 * `blob_va`. All internal references are RIP-relative, so it runs correctly at
 * any cave VA. The control block and result live *inside* the copied image at
 * fixed offsets, so the handler finds them relative to its own base and the
 * outer reads them back through the kernel read primitive.
 */

/* Offset of the blob image inside the cave scratch region. */
#define OT_ORACLE_BLOB_OFF 0x1000
/* Top of the handler stack inside the cave scratch region. */
#define OT_ORACLE_STACK_OFF 0x3000

/* Fixed offsets inside the copied blob image. */
#define OT_ORACLE_PARAM_OFF 0x800
#define OT_ORACLE_RESULT_OFF 0xC00

#define OT_ORACLE_RESULT_MAGIC 0x4F54524553555441ULL /* 'OTRESUTA' */

/* struct ot_oracle_ctl field offsets (see struct below). */
#define OT_CTL_MODE 0x00
#define OT_CTL_CANDIDATE 0x08
#define OT_CTL_RSP 0x10
#define OT_CTL_GREGS 0x18

#define OT_CTL_G_RAX 0x18
#define OT_CTL_G_RCX 0x20
#define OT_CTL_G_RDX 0x28
#define OT_CTL_G_RBX 0x30
#define OT_CTL_G_RBP 0x38
#define OT_CTL_G_RSI 0x40
#define OT_CTL_G_RDI 0x48
#define OT_CTL_G_R8 0x50
#define OT_CTL_G_R9 0x58
#define OT_CTL_G_R10 0x60
#define OT_CTL_G_R11 0x68
#define OT_CTL_G_R12 0x70
#define OT_CTL_G_R13 0x78
#define OT_CTL_G_R14 0x80
#define OT_CTL_G_R15 0x88

#define OT_CTL_SAVED_RIP 0x90
#define OT_CTL_SAVED_CS 0x98
#define OT_CTL_SAVED_RFLAGS 0xA0
#define OT_CTL_SAVED_RSP 0xA8
#define OT_CTL_SAVED_SS 0xB0
#define OT_CTL_SAVED_GREGS 0xB8
/* 0xB8 + 120 = 0x130 */

/* Handler return actions (asm dispatch on eax). */
#define OT_ACT_RETURN 0
#define OT_ACT_STEP 1
#define OT_ACT_RET_USER 2

/* Modes. */
#define OT_MODE_RECORD 0
#define OT_MODE_STEP 1

#ifndef __ASSEMBLER__
#include <stdint.h>

/* Saved GPRs in push order (entry.S). Memory index matches the SysV order. */
struct ot_oracle_gregs {
  uint64_t rax, rcx, rdx, rbx, rbp, rsi, rdi;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
};

struct ot_oracle_ctl {
  uint64_t mode;      /* OT_MODE_* */
  uint64_t candidate; /* address to single-step */
  uint64_t ctl_rsp;   /* controlled stack for the candidate */
  struct ot_oracle_gregs gregs;       /* controlled GPR seed values */
  uint64_t saved_rip, saved_cs, saved_rflags, saved_rsp, saved_ss;
  struct ot_oracle_gregs saved_gregs; /* user context to restore */
};

struct ot_oracle_result {
  uint64_t magic;
  uint64_t entries;
  uint64_t frame_rip, frame_cs, frame_rflags, frame_rsp, frame_ss;
  struct ot_oracle_gregs gregs;
  uint64_t dr6;
};
#endif /* __ASSEMBLER__ */

#endif /* OT_ORACLE_LAYOUT_H */
