# Freestanding #DB-handler blob for the gadget-free execution oracle.
# Builds a position-independent, VA-0-linked blob and embeds it as a C array.

CC      := gcc
LD      := ld
OBJCOPY := objcopy
BIN2C   := ../../../../scripts/bin2c.py

CFLAGS := -O2 -ffreestanding -nostdlib -fno-pic -fno-plt \
  -fno-stack-protector -fno-stack-clash-protection \
  -fomit-frame-pointer -fno-asynchronous-unwind-tables \
  -fcf-protection=none -fno-jump-tables -mgeneral-regs-only \
  -mno-red-zone -mno-sse -Wall -Wextra

OBJ    := ot_oracle_payload.o ot_oracle_entry.o
TARGET := ot_oracle_blob.elf
BIN    := ot_oracle_blob.bin
DUMP   := ot_oracle_blob.h

all: $(DUMP)

$(TARGET): $(OBJ) link.ld
	$(LD) -nostdlib -no-pie -T link.ld $(OBJ) -o $(TARGET)

ot_oracle_payload.o: ot_oracle_payload.c ot_oracle_layout.h
	$(CC) $(CFLAGS) -c $< -o $@

ot_oracle_entry.o: ot_oracle_entry.S
	$(CC) -c $< -o $@

$(BIN): $(TARGET)
	$(OBJCOPY) -O binary $(TARGET) $(BIN)

$(DUMP): $(BIN) $(BIN2C)
	python3 $(BIN2C) $(BIN) > $(DUMP)

clean:
	rm -f $(OBJ) $(TARGET) $(BIN) $(DUMP)
.PHONY: all clean
