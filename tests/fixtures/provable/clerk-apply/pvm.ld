/* Canonical standard-PVM layout for a large proof Task.
 *
 * The read-write base is derived from the final read-only size, matching the
 * standard-program layout instead of relying on a stale fixed address.
 */

ENTRY(_start)

SECTIONS
{
    .rodata 0x10000 : { *(.rodata .rodata.* .srodata .srodata.*) }
    .data (0x20000 + ((SIZEOF(.rodata) + 0xffff) & ~0xffff)) :
        { *(.data .data.* .sdata .sdata.*) }
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .text 0x900000 : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
