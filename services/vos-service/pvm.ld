/* Canonical generic-service layout.
 *
 * The transpiler derives the PVM stack size from the lowest read-only ELF
 * address. Root-service Accumulate decodes nested causal checkpoints and
 * therefore reserves 256 KiB; ordinary application actors retain the target
 * default. Code addresses are linker-only inputs and are remapped by the
 * transpiler into the canonical PVM program.
 */

ENTRY(_start)

SECTIONS
{
    .rodata 0x40000 : { *(.rodata .rodata.* .srodata .srodata.*) }
    .text ALIGN(0x1000) : { *(.text .text.* .init .init.*) }
    .data ALIGN(0x1000) : { *(.data .data.* .sdata .sdata.*) }
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
