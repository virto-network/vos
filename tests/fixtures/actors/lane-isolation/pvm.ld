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
