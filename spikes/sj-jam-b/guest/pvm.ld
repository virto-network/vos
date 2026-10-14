/* Gray Paper standard-program layout: read-only data at Z_Z, read-write data
 * (including .bss) from 2*Z_Z + zone_round(|ro|), set explicitly. An actor
 * program's schema (.vos_schema) comes first in the read-only data, where
 * the agent and the node look for it. */

ENTRY(_start)

SECTIONS
{
    .rodata 0x10000 : { KEEP(*(.vos_schema)) *(.rodata .rodata.* .srodata .srodata.*) }
    . = 0x20000 + ((SIZEOF(.rodata) + 0xffff) & ~0xffff);
    /* The GOT and relocated read-only data are written at link time, so
     * they belong with the read-write data, not after .rodata. */
    .data : { *(.data .data.* .sdata .sdata.* .got .got.* .data.rel.ro .data.rel.ro.*) }
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    /* Code has its own address space on the PVM, so its ELF address only has
     * to stay within PC-relative reach of the data. It follows the data, so a
     * large .bss (a heap arena) never overlaps it. */
    .text ALIGN(0x10000) : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
