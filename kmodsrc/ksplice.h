#include <linux/types.h>

/**
 * struct ksplice_symbol - Ksplice's analogue of an ELF symbol
 * @name:		The ELF name of the symbol
 * @label:		A unique Ksplice name for the symbol
 * @candidate_vals:	A linked list of possible values for the symbol, or NULL
 * @value:		The value of the symbol (valid when vals is NULL)
 **/
struct ksplice_symbol {
	const char *name;
	const char *label;
/* private: */
	struct list_head *candidate_vals;
	unsigned long value;
};

/**
 * struct ksplice_reloc - Ksplice's analogue of an ELF relocation
 * @blank_addr:		The address of the relocation's storage unit
 * @symbol:		The ksplice_symbol associated with this relocation
 * @howto:		The information regarding the relocation type
 * @insn_addend:	The part of the ELF addend resulting from quirks of
 *			the instruction one of whose operands is the relocation.
 *			For example, this is -4 on x86 pc-relative jumps.
 * @target_addend:	The rest of the ELF addend.  This is equal to the offset
 *			against the symbol that the relocation refers to.
 **/
struct ksplice_reloc {
	unsigned long blank_addr;
	struct ksplice_symbol *symbol;
	const struct ksplice_reloc_howto *howto;
	long insn_addend;
	long target_addend;
};

enum ksplice_reloc_howto_type {
	KSPLICE_HOWTO_RELOC,
	KSPLICE_HOWTO_RELOC_PATCH,
	KSPLICE_HOWTO_DATE,
	KSPLICE_HOWTO_TIME,
	KSPLICE_HOWTO_BUG,
	KSPLICE_HOWTO_EXTABLE,
	KSPLICE_HOWTO_SYMBOL,
};

/**
 * struct ksplice_reloc_howto - Ksplice's relocation type information
 * @type:		The type of the relocation
 * @pcrel:		Is the relocation PC relative?
 * @size:		The size, in bytes, of the item to be relocated
 * @dst_mask:		Bitmask for which parts of the instruction or data are
 * 			replaced with the relocated value
 * 			(based on dst_mask from GNU BFD's reloc_howto_struct)
 * @rightshift:		The value the final relocation is shifted right by;
 * 			used to drop unwanted data from the relocation
 * 			(based on rightshift from GNU BFD's reloc_howto_struct)
 * @signed_addend:	Should the addend be interpreted as a signed value?
 **/
struct ksplice_reloc_howto {
	enum ksplice_reloc_howto_type type;
	int pcrel;
	int size;
	long dst_mask;
	unsigned int rightshift;
	int signed_addend;
};

#if BITS_PER_LONG == 32
#define KSPLICE_CANARY 0x77777777UL
#elif BITS_PER_LONG == 64
#define KSPLICE_CANARY 0x7777777777777777UL
#endif /* BITS_PER_LONG */

/**
 * struct ksplice_section - Ksplice's analogue of an ELF section
 * @symbol:		The ksplice_symbol associated with this section
 * @size:		The length, in bytes, of this section
 * @address:		The address of the section
 * @flags:		Flags indicating the type of the section, whether or
 *			not it has been matched, etc.
 **/
struct ksplice_section {
	struct ksplice_symbol *symbol;
	unsigned long address;
	unsigned long size;
	unsigned int flags;
	const unsigned char **match_map;
	int unmatched;
};
#define KSPLICE_SECTION_TEXT 0x00000001
#define KSPLICE_SECTION_RODATA 0x00000002
#define KSPLICE_SECTION_DATA 0x00000004
#define KSPLICE_SECTION_STRING 0x00000008
#define KSPLICE_SECTION_MATCH_DATA_EARLY 0x00000100
#define KSPLICE_SECTION_MATCHED 0x10000000

#define MAX_TRAMPOLINE_SIZE 5

enum ksplice_patch_type {
	KSPLICE_PATCH_TEXT,
	KSPLICE_PATCH_DATA,
	KSPLICE_PATCH_EXPORT,
};

/**
 * struct ksplice_patch - A replacement that Ksplice should perform
 * @oldaddr:		The address of the obsolete function or structure
 * @repladdr:		The address of the replacement function
 * @type:		The type of the ksplice patch
 * @size:		The size of the patch
 * @contents:		The bytes to be installed at oldaddr
 * @vaddr		The address of the page mapping used to write at oldaddr
 * @saved:		The bytes originally at oldaddr which were
 * 			overwritten by the patch
 **/
struct ksplice_patch {
	unsigned long oldaddr;
	unsigned long repladdr;
	enum ksplice_patch_type type;
	unsigned int size;
	void *contents;
/* private: */
	void *vaddr;
	void *saved;
};

#ifdef KSPLICE_STANDALONE
struct ksplice_system_map {
	const char *label;
	unsigned long nr_candidates;
	const unsigned long *candidates;
};
#endif /* KSPLICE_STANDALONE */

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/stringify.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* 6e21828743247270d09a86756a0c11702500dbfb was after 2.6.18 */
#define bool _Bool
#define false 0
#define true 1
#endif /* LINUX_VERSION_CODE */

#if defined(CONFIG_PARAVIRT) && defined(CONFIG_X86_64) &&	\
    LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25) &&		\
    LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/* Linux 2.6.25 and 2.6.26 apply paravirt replacements to the core
 * kernel but not modules on x86-64.  If we are patching the core
 * kernel, we need to apply the same replacements to our update
 * modules in order for run-pre matching to succeed.
 */
#define KSPLICE_NEED_PARAINSTRUCTIONS 1
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */

#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)
#define KSPLICE_UNIQ(s) PASTE(s##_, KSPLICE_MID)
#define KSPLICE_KID_UNIQ(s) PASTE(s##_, KSPLICE_KID)
#ifdef KSPLICE_STANDALONE
#define init_ksplice_mod_change KSPLICE_KID_UNIQ(init_ksplice_mod_change)
#define cleanup_ksplice_mod_change KSPLICE_KID_UNIQ(cleanup_ksplice_mod_change)
#endif

/**
 * struct ksplice_module_list_entry - A record of a ksplice_mod_change's target
 * @target_mod_name:	The name of the ksplice_mod_change's target module
 * @new_code_mod_name:	The name of the ksplice_mod_change's new_code module
 * @applied:		Whether the ksplice_mod_change was applied or not (this
 *			will be false for ksplice_mod_changes patching targets
 *			that are not loaded when the partial flag is set)
 **/
struct ksplice_module_list_entry {
	const char *target_mod_name;
	const char *new_code_mod_name;
	const char *kid;
	bool applied;
/* private: */
	struct list_head update_list;	/* list head for this is per-update */
	struct list_head list;	/* list head for this is global */
};

/* List of all ksplice modules and the module they patch */
extern struct list_head ksplice_modules;

/* There are two actions, apply and reverse */
#define KS_ACTIONS 2
enum ksplice_action {
	KS_APPLY,
	KS_REVERSE,
};

/**
 * struct ksplice_hooks - Hooks to be run during an action (apply or reverse)
 * @pre:			Runs before the action;
 * 				may return nonzero to abort the action
 * @check:			Runs inside stop_machine before the action;
 * 				may return nonzero to abort the action
 * @intra:			Runs inside stop_machine during the action
 * @post:			Runs after the action is successfully performed
 * @fail:			Runs if the action is aborted for any reason
 */
struct ksplice_hooks {
	const typeof(int (*)(void)) *pre, *pre_end, *check, *check_end;
	const typeof(void (*)(void)) *intra, *intra_end, *post, *post_end,
	    *fail, *fail_end;
};

/**
 * struct ksplice_code - Ksplice metadata for an object
 * @relocs:		The Ksplice relocations for the object
 * @symbols:		The Ksplice symbols for the object
 * @sections:		The Ksplice sections for the object
 **/
struct ksplice_code {
	struct ksplice_reloc *relocs, *relocs_end;
	struct ksplice_section *sections, *sections_end;
	struct ksplice_symbol *symbols, *symbols_end;
#ifdef KSPLICE_NEED_PARAINSTRUCTIONS
	struct paravirt_patch_site *parainstructions, *parainstructions_end;
#endif /* KSPLICE_NEED_PARAINSTRUCTIONS */
#ifdef KSPLICE_STANDALONE
	struct ksplice_system_map *system_map, *system_map_end;
#endif /* KSPLICE_STANDALONE */
};

/**
 * struct ksplice_mod_change - Data for one module modified by a Ksplice update
 * @name:			The name of the new_code module for the change
 * @kid:			The Ksplice unique identifier for the change
 * @target_name:		The name of the module modified by the change
 * @new_code_mod:		The new_code module for the change
 * @old_code:			The old code for run-pre matching
 * @new_code:			The new code to switch to
 * @patches:			The function replacements in the change
 * @patches_end:		The end pointer for patches array
 * @hooks:			Hooks to be run during apply and reverse
 * @update:			The atomic update the change is part of
 * @target:			The module modified by the change
 * @safety_records:		The ranges of addresses that must not be on a
 *				kernel stack for the patch to apply safely
 **/
struct ksplice_mod_change {
	const char *name;
	const char *kid;
	const char *target_name;
#ifdef KSPLICE_STANDALONE
	unsigned long map_printk;
#endif /* KSPLICE_STANDALONE */
	struct module *new_code_mod;
	struct ksplice_code old_code, new_code;
	struct ksplice_patch *patches, *patches_end;
	struct ksplice_hooks hooks[KS_ACTIONS];
/* private: */
	struct update *update;
	struct module *target;
	struct list_head temp_labelvals;
	struct list_head safety_records;
	struct list_head list;
};


int init_ksplice_mod_change(struct ksplice_mod_change *change);

void cleanup_ksplice_mod_change(struct ksplice_mod_change *change);

#endif /* __KERNEL__ */
