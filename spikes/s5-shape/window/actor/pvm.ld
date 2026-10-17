/* Gray Paper standard-program layout: read-only data at Z_Z, read-write data
 * (including .bss, then the heap's arena) from 2*Z_Z + zone_round(|ro|), set
 * explicitly. An actor
 * program's schema comes first in the read-only data, a section of its own
 * (.vos_schema) where the agent looks for it and the ELF describes itself,
 * then the table of its attestable methods' entries (.vos_attest), the
 * roots its kernels are derived from. */

ENTRY(_start)

SECTIONS
{
    . = 0x10000;
    .vos_schema : { KEEP(*(.vos_schema)) }
    .rodata : { KEEP(*(.vos_attest)) *(.rodata .rodata.* .srodata .srodata.*) }
    . = 0x20000 + ((. - 0x10000 + 0xffff) & ~0xffff);
    /* The GOT and relocated read-only data are written at link time, so
     * they belong with the read-write data, not after .rodata. */
    .data : { *(.data .data.* .sdata .sdata.* .got .got.* .data.rel.ro .data.rel.ro.*) }
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    /* The heap's arena ends the read-write data, so a program may map a
     * part of it: a derivation's programs for handlers and kernels hold
     * its start, and a workflow's machine maps the rest. */
    .vos_heap ALIGN(0x1000) (NOLOAD) : { KEEP(*(.vos_heap)) }
    /* Code has its own address space on the PVM, so its ELF address only has
     * to stay within PC-relative reach of the data. It follows the data, so a
     * large .bss (a heap arena) never overlaps it. */
    .text ALIGN(0x10000) : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
