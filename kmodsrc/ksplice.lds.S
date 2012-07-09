#define PTR_KEEP_SQUASH(section) \
  .##section : { \
    section = .; \
    KEEP(*(.##section##*)) \
    section##_end = .; \
  }
#define PTR_KEEP(section) \
  .##section : { \
    section = .; \
    KEEP(*(.##section)) \
    section##_end = .; \
  }
SECTIONS {
  .text : { *(.text .text.* .exit.text .sched.text) }
  PTR_KEEP_SQUASH(ksplice_relocs)
  PTR_KEEP_SQUASH(ksplice_sections)
  PTR_KEEP_SQUASH(ksplice_patches)
  PTR_KEEP(ksplice_symbols)
  PTR_KEEP(ksplice_system_map)
  PTR_KEEP(ksplice_call_pre_apply)
  PTR_KEEP(ksplice_call_check_apply)
  PTR_KEEP(ksplice_call_apply)
  PTR_KEEP(ksplice_call_post_apply)
  PTR_KEEP(ksplice_call_fail_apply)
  PTR_KEEP(ksplice_call_pre_reverse)
  PTR_KEEP(ksplice_call_check_reverse)
  PTR_KEEP(ksplice_call_reverse)
  PTR_KEEP(ksplice_call_post_reverse)
  PTR_KEEP(ksplice_call_fail_reverse)
  PTR_KEEP(parainstructions)
}
