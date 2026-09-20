/* Canonical scheduled custom AgentRuntime layout. */
ENTRY(_start)

SECTIONS
{
    .rodata 0x40000 : { *(.rodata .rodata.* .srodata .srodata.*) }
    /* GP reserves a guard zone after the page-rounded read-only region.
     * This also accommodates the test-only scripted fixture's case table. */
    __rw_base = ALIGN(ADDR(.rodata) + SIZEOF(.rodata), 0x10000) + 0x10000;
    .data __rw_base : { *(.data .data.* .sdata .sdata.*) }
    /* An empty .data output section does not advance the linker location
     * counter. Keep zero-initialized guest memory above GP's read-write base
     * even when this runtime has no initialized writable statics. */
    . = MAX(., __rw_base);
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .text 0x3000000 : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
