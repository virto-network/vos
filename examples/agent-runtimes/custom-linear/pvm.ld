/* Canonical custom AgentRuntime layout. */
ENTRY(_start)

SECTIONS
{
    .rodata 0x40000 : { *(.rodata .rodata.* .srodata .srodata.*) }
    .data 0x60000 : { *(.data .data.* .sdata .sdata.*) }
    /* An empty .data output section does not advance the linker location
     * counter. Keep zero-initialized guest memory above GP's read-write base
     * even when this runtime has no initialized writable statics. */
    . = MAX(., 0x60000);
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .text 0x3000000 : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
