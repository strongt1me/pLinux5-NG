ENTRY(ot_oracle_entry)
SECTIONS
{
  . = 0;
  .text : {
    *(.text.ot_oracle_entry)
    *(.text .text.*)
    *(.rodata .rodata.*)
  }

  /* Pad the image out to one page so the PARAM/RESULT regions at 0x800/0x900
   * are part of the copied blob. */
  . = 0xFFF;
  .pad : { BYTE(0); }

  /DISCARD/ : {
    *(.eh_frame .eh_frame_hdr)
    *(.note .note.*)
    *(.comment)
    *(.data .data.*)
    *(.bss .bss.*)
  }
}
