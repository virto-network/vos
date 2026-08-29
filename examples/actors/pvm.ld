/* Canonical standard-PVM actor layout.
 *
 * Read-only and read-write data occupy distinct GP zones. Actor stacks and
 * arguments are mapped separately by the agent runtime; code has its own
 * instruction address space.
 */

ENTRY(_start)

SECTIONS
{
    .rodata 0x10000 : { *(.rodata .rodata.* .srodata .srodata.*) }
    .data 0x30000 : { *(.data .data.* .sdata .sdata.*) }
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .text 0x900000 : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
