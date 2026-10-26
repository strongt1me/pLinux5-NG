.PHONY: all clean clean-objs version payload offsets-tool

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN   := bin/pLinux5-NG.elf
OTBIN := bin/offsets-tool.elf

# ----------------------------------------------------------------- payload ---
SRC  := $(wildcard source/*.c source/core/*.c source/hw/*.c source/boot/*.c source/manifest/*.c source/offsets/linux/*.c source/hv/defeat/*.c)
OBJS := $(SRC:.c=.o)

# ----------------------------------------------------------------- offsets ---
# The tool tree is split by concern; oracle/ also builds the freestanding
# execution-oracle blob, so its sources are listed explicitly rather than
# wildcarded (the blob payload is compiled by oracle/Makefile, not here).
OT_SRC  := \
	source/tools/offsets/core/main.c \
	source/tools/offsets/core/ot_env.c \
	source/tools/offsets/discovery/escape.c \
	source/tools/offsets/discovery/ot_find.c \
	source/tools/offsets/discovery/ot_harvest.c \
	source/tools/offsets/dump/ot_dump.c \
	source/tools/offsets/dump/miniz.c \
	source/tools/offsets/defeat/ot_defeat.c \
	source/tools/offsets/oracle/ot_oracle.c
OT_OBJS := $(OT_SRC:.c=.o)

# Vendored Byepervisor port (kdlsym/khook/paging) + per-firmware offset tables.
# Compiled once and linked into both the payload and the offsets tool.
SHARED_OBJS := source/byepervisor/kdlsym.o source/byepervisor/khook.o \
               source/byepervisor/paging.o \
               $(patsubst %.c,%.o,$(wildcard source/offsets/byepervisor/*.c))

# Project identity lives in source/manifest/manifest.c (see include/manifest.h).
# Its .version is the single source of truth - CI reads the same field to name
# releases, so the ELF and the release cannot disagree.
MANIFEST_C := source/manifest/manifest.c
manifest-field = $(shell sed -n 's/^[[:space:]]*\.$(2)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' $(1))
PL5_VERSION := $(call manifest-field,$(MANIFEST_C),version)
ifeq ($(strip $(PL5_VERSION)),)
$(error could not read .version from $(MANIFEST_C))
endif

# Diagnostic bisection stage (see source/hv/defeat/hv_defeat_1320.c). Override on the
# command line, e.g. `make PL5_DIAG=1`. Remember to clear the objects first
# (the flag does not retrigger a rebuild on its own): `make -C . clean-objs`.
PL5_DIAG ?= 4
# Takeover-blob step selector (see source/shellcode/hv_takeover/takeover.S).
PL5_TAKEOVER_STAGE ?= 3
# Pre-rest-mode resume_rip probe (source/hv/defeat/hv_defeat_1320.c). Off by default so
# PL5_DIAG=4 runs the real post-resume flow; set to 1 for the probe build.
PL5_PROBE ?= 0
# shellcode_hv checkpoint bisection (source/shellcode/hv/boot_linux.c): freeze at a
# checkpoint instead of booting. 0=full boot, 1=entry, 2=post-configure_vram,
# 3=post-barrier.
PL5_HV_STOP ?= 0

# Include search paths shared by the payload and the offsets tool.
INC := -Iinclude -Iinclude/core -Iinclude/hw -Iinclude/boot -Iinclude/byepervisor \
       -Iinclude/hv/defeat -Iinclude/manifest -Iinclude/offsets \
       -Isource/shellcode/hv -Isource/shellcode/kernel -Isource/shellcode/break_hv \
       -Isource/shellcode/hv_boot -Isource/shellcode/hv_takeover

CFLAGS    := -std=c23 -Wall -DPL5_DIAG=$(PL5_DIAG) -DPL5_TAKEOVER_STAGE=$(PL5_TAKEOVER_STAGE) -DPL5_PROBE=$(PL5_PROBE) $(INC)
OT_CFLAGS := -std=c23 -Wall $(INC) \
             -Iinclude/tools/offsets/core -Iinclude/tools/offsets/discovery \
             -Iinclude/tools/offsets/dump -Iinclude/tools/offsets/defeat \
             -Iinclude/tools/offsets/oracle -Isource/tools/offsets/oracle
# pLabs5 toolchain override (see PORTING.md). Pass LLVM_CONFIG in the environment:
#   export LLVM_CONFIG=/nyaa/coding/public/PS5/dRPC5/pLabs5-SDK/tools/nixos/llvm-config
LDFLAGS :=

SC_0607_H := source/shellcode/0607/shellcode_0607.h
SC_HV_H := source/shellcode/hv/shellcode_hv.h
SC_K_H  := source/shellcode/kernel/shellcode_kernel.h
SC_BREAK_H := source/shellcode/break_hv/break_hv.h
SC_BOOT_H := source/shellcode/hv_boot/hv_boot.h
SC_TAKEOVER_H := source/shellcode/hv_takeover/takeover.h
SC_ORACLE_H := source/tools/offsets/oracle/ot_oracle_blob.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(SC_ORACLE_H) $(BIN) $(OTBIN)

# Print the manifest version (read from source/manifest/manifest.c).
version:
	@printf '%s\n' '$(PL5_VERSION)'

# Convenience targets to build a single artifact.
payload: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H) $(BIN)
offsets-tool: $(SC_BREAK_H) $(SC_ORACLE_H) $(OTBIN)

$(SC_0607_H):
	$(MAKE) -C source/shellcode/0607

$(SC_HV_H):
	$(MAKE) -C source/shellcode/hv PL5_HV_STOP=$(PL5_HV_STOP)

$(SC_K_H): $(SC_HV_H)
	$(MAKE) -C source/shellcode/kernel

$(SC_BREAK_H):
	$(MAKE) -C source/shellcode/break_hv

$(SC_BOOT_H):
	$(MAKE) -C source/shellcode/hv_boot

$(SC_TAKEOVER_H):
	$(MAKE) -C source/shellcode/hv_takeover

$(SC_ORACLE_H):
	$(MAKE) -C source/tools/offsets/oracle

# Shared objects (byepervisor port + offset tables).
$(SHARED_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Payload objects.
$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# The userland objects include the generated shellcode headers; make the
# dependency explicit so `make -j` cannot compile them before the blobs exist.
$(OBJS): $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_BREAK_H) $(SC_BOOT_H) $(SC_TAKEOVER_H)

$(BIN): $(OBJS) $(SHARED_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $^ $(LDFLAGS) -o $@

# Offsets-tool objects.
$(OT_OBJS): %.o: %.c
	$(CC) $(OT_CFLAGS) -c -o $@ $<

# ot_defeat.c embeds the break_hv blob; ot_oracle.c embeds the oracle blob. The
# oracle header is an extra prerequisite on top of the generic %.o: %.c rule.
$(OT_OBJS): $(SC_BREAK_H)
source/tools/offsets/oracle/ot_oracle.o: $(SC_ORACLE_H)

$(OTBIN): $(OT_OBJS) $(SHARED_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $^ $(LDFLAGS) -o $@

clean-objs:
	rm -f $(OBJS) $(SHARED_OBJS) $(OT_OBJS)

clean:
	rm -f $(BIN) $(OBJS) $(SHARED_OBJS) $(OTBIN) $(OT_OBJS)
	$(MAKE) -C source/shellcode/0607 clean
	$(MAKE) -C source/shellcode/hv clean
	$(MAKE) -C source/shellcode/kernel clean
	$(MAKE) -C source/shellcode/break_hv clean
	$(MAKE) -C source/shellcode/hv_boot clean
	$(MAKE) -C source/shellcode/hv_takeover clean
	$(MAKE) -C source/tools/offsets/oracle clean
