/*  Copyright (C) 2007-2009  Ksplice, Inc.
 *  Authors: Jeff Arnold, Anders Kaseorg, Tim Abbott
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kobject.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sort.h>
#include <linux/stop_machine.h>
#include <linux/sysfs.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#ifdef KSPLICE_STANDALONE
#include "ksplice.h"
#else /* !KSPLICE_STANDALONE */
#include <linux/ksplice.h>
#endif /* KSPLICE_STANDALONE */

#ifdef KSPLICE_STANDALONE
#if !defined(CONFIG_KSPLICE) && !defined(CONFIG_KSPLICE_MODULE)
#define KSPLICE_NO_KERNEL_SUPPORT 1
#endif /* !CONFIG_KSPLICE && !CONFIG_KSPLICE_MODULE */

#ifndef __used
#define __used __attribute_used__
#endif

#define EXTRACT_SYMBOL(sym)						\
	static const typeof(&sym) KS_PASTE(__ksplice_extract_, __LINE__)	\
	    __used __attribute__((section(".ksplice_extract"))) = &sym
#endif /* KSPLICE_STANDALONE */

enum stage {
	STAGE_PREPARING,	/* the update is not yet applied */
	STAGE_APPLIED,		/* the update is applied */
	STAGE_REVERSED,		/* the update has been applied and reversed */
};

/* parameter to modify run-pre matching */
enum run_pre_mode {
	RUN_PRE_INITIAL,	/* dry run (only change temp_labelvals) */
	RUN_PRE_DEBUG,		/* dry run with byte-by-byte debugging */
	RUN_PRE_FINAL,		/* finalizes the matching */
#ifndef CONFIG_FUNCTION_DATA_SECTIONS
	RUN_PRE_SILENT,
#endif /* !CONFIG_FUNCTION_DATA_SECTIONS */
};

enum { NOVAL, TEMP, VAL };

typedef int __bitwise__ abort_t;

#define OK ((__force abort_t) 0)
#define NO_MATCH ((__force abort_t) 1)
#define CODE_BUSY ((__force abort_t) 2)
#define MODULE_BUSY ((__force abort_t) 3)
#define OUT_OF_MEMORY ((__force abort_t) 4)
#define FAILED_TO_FIND ((__force abort_t) 5)
#define ALREADY_REVERSED ((__force abort_t) 6)
#define MISSING_EXPORT ((__force abort_t) 7)
#define UNEXPECTED_RUNNING_TASK ((__force abort_t) 8)
#define UNEXPECTED ((__force abort_t) 9)
#define TARGET_NOT_LOADED ((__force abort_t) 10)
#define CALL_FAILED ((__force abort_t) 11)
#define COLD_UPDATE_LOADED ((__force abort_t) 12)
#ifdef KSPLICE_STANDALONE
#define BAD_SYSTEM_MAP ((__force abort_t) 13)
#endif /* KSPLICE_STANDALONE */

struct update {
	const char *kid;
	const char *name;
	struct kobject kobj;
	enum stage stage;
	abort_t abort_cause;
	int debug;
#ifdef CONFIG_DEBUG_FS
	struct debugfs_blob_wrapper debug_blob;
	struct dentry *debugfs_dentry;
#else /* !CONFIG_DEBUG_FS */
	bool debug_continue_line;
#endif /* CONFIG_DEBUG_FS */
	bool partial;		/* is it OK if some target mods aren't loaded */
	struct list_head changes,	/* changes for loaded target mods */
	    unused_changes;		/* changes for non-loaded target mods */
	struct list_head conflicts;
	struct list_head list;
	struct list_head ksplice_module_list;
};

/* a process conflicting with an update */
struct conflict {
	const char *process_name;
	pid_t pid;
	struct list_head stack;
	struct list_head list;
};

/* an address on the stack of a conflict */
struct conflict_addr {
	unsigned long addr;	/* the address on the stack */
	bool has_conflict;	/* does this address in particular conflict? */
	const char *label;	/* the label of the conflicting safety_record */
	struct list_head list;
};

struct labelval {
	struct list_head list;
	struct ksplice_symbol *symbol;
	struct list_head *saved_vals;
};

/* region to be checked for conflicts in the stack check */
struct safety_record {
	struct list_head list;
	const char *label;
	unsigned long addr;	/* the address to be checked for conflicts
				 * (e.g. an obsolete function's starting addr)
				 */
	unsigned long size;	/* the size of the region to be checked */
};

/* possible value for a symbol */
struct candidate_val {
	struct list_head list;
	unsigned long val;
};

/* private struct used by init_symbol_array */
struct ksplice_lookup {
/* input */
	struct ksplice_mod_change *change;
	struct ksplice_symbol **arr;
	size_t size;
/* output */
	abort_t ret;
};

static LIST_HEAD(updates);
#ifdef KSPLICE_STANDALONE
#if defined(CONFIG_KSPLICE) || defined(CONFIG_KSPLICE_MODULE)
extern struct list_head ksplice_modules;
#else /* !CONFIG_KSPLICE */
LIST_HEAD(ksplice_modules);
#endif /* CONFIG_KSPLICE */
#else /* !KSPLICE_STANDALONE */
LIST_HEAD(ksplice_modules);
EXPORT_SYMBOL_GPL(ksplice_modules);
static struct kobject *ksplice_kobj;
#endif /* KSPLICE_STANDALONE */

static struct kobj_type update_ktype;

#ifdef KSPLICE_STANDALONE

#ifdef do_each_thread_ve		/* OpenVZ kernels define this */
#define do_each_thread do_each_thread_all
#define while_each_thread while_each_thread_all
#endif

static bool bootstrapped = false;

/* defined by ksplice-create */
extern const struct ksplice_reloc ksplice_init_relocs[],
    ksplice_init_relocs_end[];

#endif /* KSPLICE_STANDALONE */

static struct update *init_ksplice_update(const char *kid);
static void cleanup_ksplice_update(struct update *update);
static void maybe_cleanup_ksplice_update(struct update *update);
static void add_to_update(struct ksplice_mod_change *change,
			  struct update *update);
static int ksplice_sysfs_init(struct update *update);

/* Preparing the relocations and patches for application */
static abort_t apply_update(struct update *update);
static abort_t reverse_update(struct update *update);
static abort_t prepare_change(struct ksplice_mod_change *change);
static abort_t finalize_change(struct ksplice_mod_change *change);
static abort_t finalize_patches(struct ksplice_mod_change *change);
static abort_t add_dependency_on_address(struct ksplice_mod_change *change,
					 unsigned long addr);
static abort_t map_trampoline_pages(struct update *update);
static void unmap_trampoline_pages(struct update *update);
static void *map_writable(void *addr, size_t len);
static abort_t apply_relocs(struct ksplice_mod_change *change,
			    const struct ksplice_reloc *relocs,
			    const struct ksplice_reloc *relocs_end);
static abort_t apply_reloc(struct ksplice_mod_change *change,
			   const struct ksplice_reloc *r);
static abort_t apply_howto_reloc(struct ksplice_mod_change *change,
				 const struct ksplice_reloc *r);
static abort_t apply_howto_date(struct ksplice_mod_change *change,
				const struct ksplice_reloc *r);
static abort_t read_reloc_value(struct ksplice_mod_change *change,
				const struct ksplice_reloc *r,
				unsigned long addr, unsigned long *valp);
static abort_t write_reloc_value(struct ksplice_mod_change *change,
				 const struct ksplice_reloc *r,
				 unsigned long addr, unsigned long sym_addr);
static abort_t create_module_list_entry(struct ksplice_mod_change *change,
					bool to_be_applied);
static void cleanup_module_list_entries(struct update *update);
static void __attribute__((noreturn)) ksplice_deleted(void);

/* run-pre matching */
static abort_t match_change_sections(struct ksplice_mod_change *change,
				   bool consider_data_sections);
static abort_t find_section(struct ksplice_mod_change *change,
			    struct ksplice_section *sect);
static abort_t try_addr(struct ksplice_mod_change *change,
			struct ksplice_section *sect,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode);
static abort_t run_pre_cmp(struct ksplice_mod_change *change,
			   const struct ksplice_section *sect,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode);
#ifndef CONFIG_FUNCTION_DATA_SECTIONS
/* defined in arch/ARCH/kernel/ksplice-arch.c */
static abort_t arch_run_pre_cmp(struct ksplice_mod_change *change,
				struct ksplice_section *sect,
				unsigned long run_addr,
				struct list_head *safety_records,
				enum run_pre_mode mode);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
static void print_bytes(struct ksplice_mod_change *change,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec);
#if defined(KSPLICE_STANDALONE) && !defined(CONFIG_KALLSYMS)
static abort_t brute_search(struct ksplice_mod_change *change,
			    struct ksplice_section *sect,
			    const void *start, unsigned long len,
			    struct list_head *vals);
static abort_t brute_search_all(struct ksplice_mod_change *change,
				struct ksplice_section *sect,
				struct list_head *vals);
#endif /* KSPLICE_STANDALONE && !CONFIG_KALLSYMS */
static const struct ksplice_reloc *
init_reloc_search(struct ksplice_mod_change *change,
		  const struct ksplice_section *sect);
static const struct ksplice_reloc *find_reloc(const struct ksplice_reloc *start,
					      const struct ksplice_reloc *end,
					      unsigned long address,
					      unsigned long size);
static abort_t lookup_reloc(struct ksplice_mod_change *change,
			    const struct ksplice_reloc **fingerp,
			    unsigned long addr,
			    const struct ksplice_reloc **relocp);
static abort_t handle_reloc(struct ksplice_mod_change *change,
			    const struct ksplice_section *sect,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode);
static abort_t handle_howto_date(struct ksplice_mod_change *change,
				 const struct ksplice_section *sect,
				 const struct ksplice_reloc *r,
				 unsigned long run_addr,
				 enum run_pre_mode mode);
static abort_t handle_howto_reloc(struct ksplice_mod_change *change,
				  const struct ksplice_section *sect,
				  const struct ksplice_reloc *r,
				  unsigned long run_addr,
				  enum run_pre_mode mode);
#ifdef CONFIG_BUG
static abort_t handle_bug(struct ksplice_mod_change *change,
			  const struct ksplice_reloc *r,
			  unsigned long run_addr);
#endif /* CONFIG_BUG */
static abort_t handle_extable(struct ksplice_mod_change *change,
			      const struct ksplice_reloc *r,
			      unsigned long run_addr);
static struct ksplice_section *symbol_section(struct ksplice_mod_change *change,
					      const struct ksplice_symbol *sym);
static int compare_section_labels(const void *va, const void *vb);
static int symbol_section_bsearch_compare(const void *a, const void *b);
static const struct ksplice_reloc *
patch_reloc(struct ksplice_mod_change *change,
	    const struct ksplice_patch *p);

/* Computing possible addresses for symbols */
static abort_t lookup_symbol(struct ksplice_mod_change *change,
			     const struct ksplice_symbol *ksym,
			     struct list_head *vals);
static void cleanup_symbol_arrays(struct ksplice_mod_change *change);
static abort_t init_symbol_arrays(struct ksplice_mod_change *change);
static abort_t init_symbol_array(struct ksplice_mod_change *change,
				 struct ksplice_symbol *start,
				 struct ksplice_symbol *end);
static abort_t uniquify_symbols(struct ksplice_mod_change *change);
static abort_t add_matching_values(struct ksplice_lookup *lookup,
				   const char *sym_name, unsigned long sym_val);
static bool add_export_values(const struct symsearch *syms,
			      struct module *owner,
			      unsigned int symnum, void *data);
static int symbolp_bsearch_compare(const void *key, const void *elt);
static int compare_symbolp_names(const void *a, const void *b);
static int compare_symbolp_labels(const void *a, const void *b);
#ifdef CONFIG_KALLSYMS
static int add_kallsyms_values(void *data, const char *name,
			       struct module *owner, unsigned long val);
#endif /* CONFIG_KALLSYMS */
#ifdef KSPLICE_STANDALONE
static abort_t
add_system_map_candidates(struct ksplice_mod_change *change,
			  const struct ksplice_system_map *start,
			  const struct ksplice_system_map *end,
			  const char *label, struct list_head *vals);
static int compare_system_map(const void *a, const void *b);
static int system_map_bsearch_compare(const void *key, const void *elt);
#endif /* KSPLICE_STANDALONE */
static abort_t new_export_lookup(struct ksplice_mod_change *ichange,
				 const char *name, struct list_head *vals);

/* Atomic update trampoline insertion and removal */
static abort_t patch_action(struct update *update, enum ksplice_action action);
static int __apply_patches(void *update);
static int __reverse_patches(void *update);
static abort_t check_each_task(struct update *update);
static abort_t check_task(struct update *update,
			  const struct task_struct *t, bool rerun);
static abort_t check_stack(struct update *update, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack);
static abort_t check_address(struct update *update,
			     struct conflict *conf, unsigned long addr);
static abort_t check_record(struct conflict_addr *ca,
			    const struct safety_record *rec,
			    unsigned long addr);
static bool is_stop_machine(const struct task_struct *t);
static void cleanup_conflicts(struct update *update);
static void print_conflicts(struct update *update);
static void insert_trampoline(struct ksplice_patch *p);
static abort_t verify_trampoline(struct ksplice_mod_change *change,
				 const struct ksplice_patch *p);
static void remove_trampoline(const struct ksplice_patch *p);

static abort_t create_labelval(struct ksplice_mod_change *change,
			       struct ksplice_symbol *ksym,
			       unsigned long val, int status);
static abort_t create_safety_record(struct ksplice_mod_change *change,
				    const struct ksplice_section *sect,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size);
static abort_t add_candidate_val(struct ksplice_mod_change *change,
				 struct list_head *vals, unsigned long val);
static void release_vals(struct list_head *vals);
static void set_temp_labelvals(struct ksplice_mod_change *change, int status);

static int contains_canary(struct ksplice_mod_change *change,
			   unsigned long blank_addr,
			   const struct ksplice_reloc_howto *howto);
static unsigned long follow_trampolines(struct ksplice_mod_change *change,
					unsigned long addr);
static bool patches_module(const struct module *a, const struct module *b);
static bool singular(struct list_head *list);
static void *bsearch(const void *key, const void *base, size_t n,
		     size_t size, int (*cmp)(const void *key, const void *elt));
static int compare_relocs(const void *a, const void *b);
static int reloc_bsearch_compare(const void *key, const void *elt);

/* Debugging */
static abort_t init_debug_buf(struct update *update);
static void clear_debug_buf(struct update *update);
static int __attribute__((format(printf, 2, 3)))
_ksdebug(struct update *update, const char *fmt, ...);
#define ksdebug(change, fmt, ...) \
	_ksdebug(change->update, fmt, ## __VA_ARGS__)

/* Prepare a trampoline for the given patch */
static abort_t prepare_trampoline(struct ksplice_mod_change *change,
				  struct ksplice_patch *p);
/* What address does the trampoline at addr jump to? */
static abort_t trampoline_target(struct ksplice_mod_change *change,
				 unsigned long addr, unsigned long *new_addr);
/* Hook to handle pc-relative jumps inserted by parainstructions */
static abort_t handle_paravirt(struct ksplice_mod_change *change,
			       unsigned long pre, unsigned long run,
			       int *matched);
/* Is address p on the stack of the given thread? */
static bool valid_stack_ptr(const struct thread_info *tinfo, const void *p);

#ifndef KSPLICE_STANDALONE
#include "ksplice-arch.c"
#elif defined CONFIG_X86
#include "x86/ksplice-arch.c"
#elif defined CONFIG_ARM
#include "arm/ksplice-arch.c"
#endif /* KSPLICE_STANDALONE */

#define clear_list(head, type, member)				\
	do {							\
		struct list_head *_pos, *_n;			\
		list_for_each_safe(_pos, _n, head) {		\
			list_del(_pos);				\
			kfree(list_entry(_pos, type, member));	\
		}						\
	} while (0)

/**
 * init_ksplice_mod_change() - Initializes a ksplice change
 * @change:	The change to be initialized.  All of the public fields of the
 * 		change and its associated data structures should be populated
 * 		before this function is called.  The values of the private
 * 		fields will be ignored.
 **/
int init_ksplice_mod_change(struct ksplice_mod_change *change)
{
	struct update *update;
	struct ksplice_patch *p;
	struct ksplice_section *s;
	int ret = 0;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return -1;
#endif /* KSPLICE_STANDALONE */

	INIT_LIST_HEAD(&change->temp_labelvals);
	INIT_LIST_HEAD(&change->safety_records);

	sort(change->old_code.relocs,
	     change->old_code.relocs_end - change->old_code.relocs,
	     sizeof(*change->old_code.relocs), compare_relocs, NULL);
	sort(change->new_code.relocs,
	     change->new_code.relocs_end - change->new_code.relocs,
	     sizeof(*change->new_code.relocs), compare_relocs, NULL);
	sort(change->old_code.sections,
	     change->old_code.sections_end - change->old_code.sections,
	     sizeof(*change->old_code.sections), compare_section_labels, NULL);
#ifdef KSPLICE_STANDALONE
	sort(change->new_code.system_map,
	     change->new_code.system_map_end - change->new_code.system_map,
	     sizeof(*change->new_code.system_map), compare_system_map, NULL);
	sort(change->old_code.system_map,
	     change->old_code.system_map_end - change->old_code.system_map,
	     sizeof(*change->old_code.system_map), compare_system_map, NULL);
#endif /* KSPLICE_STANDALONE */

	for (p = change->patches; p < change->patches_end; p++)
		p->vaddr = NULL;
	for (s = change->old_code.sections; s < change->old_code.sections_end;
	     s++)
		s->match_map = NULL;
	for (p = change->patches; p < change->patches_end; p++) {
		const struct ksplice_reloc *r = patch_reloc(change, p);
		if (r == NULL)
			return -ENOENT;
		if (p->type == KSPLICE_PATCH_DATA) {
			s = symbol_section(change, r->symbol);
			if (s == NULL)
				return -ENOENT;
			/* Ksplice creates KSPLICE_PATCH_DATA patches in order
			 * to modify rodata sections that have been explicitly
			 * marked for patching using the ksplice-patch.h macro
			 * ksplice_assume_rodata.  Here we modify the section
			 * flags appropriately.
			 */
			if (s->flags & KSPLICE_SECTION_DATA)
				s->flags = (s->flags & ~KSPLICE_SECTION_DATA) |
				    KSPLICE_SECTION_RODATA;
		}
	}

	mutex_lock(&module_mutex);
	list_for_each_entry(update, &updates, list) {
		if (strcmp(change->kid, update->kid) == 0) {
			if (update->stage != STAGE_PREPARING) {
				ret = -EPERM;
				goto out;
			}
			add_to_update(change, update);
			ret = 0;
			goto out;
		}
	}
	update = init_ksplice_update(change->kid);
	if (update == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	ret = ksplice_sysfs_init(update);
	if (ret != 0) {
		cleanup_ksplice_update(update);
		goto out;
	}
	add_to_update(change, update);
out:
	mutex_unlock(&module_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(init_ksplice_mod_change);

/**
 * cleanup_ksplice_mod_change() - Cleans up a change if appropriate
 * @change:	The change to be cleaned up
 *
 * cleanup_ksplice_mod_change is ordinarily called twice for each
 * Ksplice update: once when the old_code module is unloaded, and once
 * when the new_code module is unloaded.  By freeing what can be freed
 * on each unload, we avoid leaks even in unusual scenarios, e.g. if
 * several alternative old_code modules are loaded and unloaded
 * successively.
 */
void cleanup_ksplice_mod_change(struct ksplice_mod_change *change)
{
	if (change->update == NULL)
		return;

	mutex_lock(&module_mutex);
	if (change->update->stage == STAGE_APPLIED) {
		struct ksplice_mod_change *c;
		bool found = false;

		list_for_each_entry(c, &change->update->unused_changes, list) {
			if (c == change)
				found = true;
		}
		if (found)
			list_del(&change->list);
		mutex_unlock(&module_mutex);
		return;
	}
	list_del(&change->list);
	if (change->update->stage == STAGE_PREPARING)
		maybe_cleanup_ksplice_update(change->update);
	change->update = NULL;
	mutex_unlock(&module_mutex);
}
EXPORT_SYMBOL_GPL(cleanup_ksplice_mod_change);

static struct update *init_ksplice_update(const char *kid)
{
	struct update *update;
	update = kcalloc(1, sizeof(struct update), GFP_KERNEL);
	if (update == NULL)
		return NULL;
	update->name = kasprintf(GFP_KERNEL, "ksplice_%s", kid);
	if (update->name == NULL) {
		kfree(update);
		return NULL;
	}
	update->kid = kstrdup(kid, GFP_KERNEL);
	if (update->kid == NULL) {
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	if (try_module_get(THIS_MODULE) != 1) {
		kfree(update->kid);
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	INIT_LIST_HEAD(&update->changes);
	INIT_LIST_HEAD(&update->unused_changes);
	INIT_LIST_HEAD(&update->ksplice_module_list);
	if (init_debug_buf(update) != OK) {
		module_put(THIS_MODULE);
		kfree(update->kid);
		kfree(update->name);
		kfree(update);
		return NULL;
	}
	list_add(&update->list, &updates);
	update->stage = STAGE_PREPARING;
	update->abort_cause = OK;
	update->partial = 0;
	INIT_LIST_HEAD(&update->conflicts);
	return update;
}

static void cleanup_ksplice_update(struct update *update)
{
	list_del(&update->list);
	cleanup_conflicts(update);
	clear_debug_buf(update);
	cleanup_module_list_entries(update);
	kfree(update->kid);
	kfree(update->name);
	kfree(update);
	module_put(THIS_MODULE);
}

/* Clean up the update if it no longer has any changes */
static void maybe_cleanup_ksplice_update(struct update *update)
{
	if (list_empty(&update->changes) && list_empty(&update->unused_changes))
		kobject_put(&update->kobj);
}

static void add_to_update(struct ksplice_mod_change *change,
			  struct update *update)
{
	change->update = update;
	list_add(&change->list, &update->unused_changes);
}

static int ksplice_sysfs_init(struct update *update)
{
	int ret = 0;
	memset(&update->kobj, 0, sizeof(update->kobj));
#ifndef KSPLICE_STANDALONE
	ret = kobject_init_and_add(&update->kobj, &update_ktype,
				   ksplice_kobj, "%s", update->kid);
#else /* KSPLICE_STANDALONE */
	ret = kobject_init_and_add(&update->kobj, &update_ktype,
				   &THIS_MODULE->mkobj.kobj, "ksplice");
#endif /* KSPLICE_STANDALONE */
	if (ret != 0)
		return ret;
	kobject_uevent(&update->kobj, KOBJ_ADD);
	return 0;
}

static abort_t apply_update(struct update *update)
{
	struct ksplice_mod_change *change, *n;
	abort_t ret;
	int retval;

	list_for_each_entry(change, &update->changes, list) {
		ret = create_module_list_entry(change, true);
		if (ret != OK)
			goto out;
	}

	list_for_each_entry_safe(change, n, &update->unused_changes, list) {
		if (strcmp(change->target_name, "vmlinux") == 0) {
			change->target = NULL;
		} else if (change->target == NULL) {
			change->target = find_module(change->target_name);
			if (change->target == NULL ||
			    !module_is_live(change->target)) {
				if (!update->partial) {
					ret = TARGET_NOT_LOADED;
					goto out;
				}
				ret = create_module_list_entry(change, false);
				if (ret != OK)
					goto out;
				continue;
			}
			retval = ref_module(change->new_code_mod,
					    change->target);
			if (retval) {
				ret = UNEXPECTED;
				goto out;
			}
		}
		ret = create_module_list_entry(change, true);
		if (ret != OK)
			goto out;
		list_del(&change->list);
		list_add_tail(&change->list, &update->changes);
	}

	list_for_each_entry(change, &update->changes, list) {
		const struct ksplice_section *sect;
		for (sect = change->new_code.sections;
		     sect < change->new_code.sections_end; sect++) {
			struct safety_record *rec = kmalloc(sizeof(*rec),
							    GFP_KERNEL);
			if (rec == NULL) {
				ret = OUT_OF_MEMORY;
				goto out;
			}
			rec->addr = sect->address;
			rec->size = sect->size;
			rec->label = sect->symbol->label;
			list_add(&rec->list, &change->safety_records);
		}
	}

	list_for_each_entry(change, &update->changes, list) {
		ret = init_symbol_arrays(change);
		if (ret != OK) {
			cleanup_symbol_arrays(change);
			goto out;
		}
		ret = prepare_change(change);
		cleanup_symbol_arrays(change);
		if (ret != OK)
			goto out;
	}
	ret = patch_action(update, KS_APPLY);
out:
	list_for_each_entry(change, &update->changes, list) {
		struct ksplice_section *s;
		if (update->stage == STAGE_PREPARING)
			clear_list(&change->safety_records,
				   struct safety_record, list);
		for (s = change->old_code.sections;
		     s < change->old_code.sections_end; s++) {
			if (s->match_map != NULL) {
				vfree(s->match_map);
				s->match_map = NULL;
			}
			s->flags &= ~KSPLICE_SECTION_MATCHED;
		}
	}
	if (update->stage == STAGE_PREPARING)
		cleanup_module_list_entries(update);

	if (ret == OK)
		printk(KERN_INFO "ksplice: Update %s applied successfully\n",
		       update->kid);
	return ret;
}

static abort_t reverse_update(struct update *update)
{
	abort_t ret;
	struct ksplice_mod_change *change;

	clear_debug_buf(update);
	ret = init_debug_buf(update);
	if (ret != OK)
		return ret;

	_ksdebug(update, "Preparing to reverse %s\n", update->kid);

	ret = patch_action(update, KS_REVERSE);
	if (ret != OK)
		return ret;

	list_for_each_entry(change, &update->changes, list)
		clear_list(&change->safety_records, struct safety_record, list);

	printk(KERN_INFO "ksplice: Update %s reversed successfully\n",
	       update->kid);
	return OK;
}

static int compare_symbolp_names(const void *a, const void *b)
{
	const struct ksplice_symbol *const *sympa = a, *const *sympb = b;
	if ((*sympa)->name == NULL && (*sympb)->name == NULL)
		return 0;
	if ((*sympa)->name == NULL)
		return -1;
	if ((*sympb)->name == NULL)
		return 1;
	return strcmp((*sympa)->name, (*sympb)->name);
}

static int compare_symbolp_labels(const void *a, const void *b)
{
	const struct ksplice_symbol *const *sympa = a, *const *sympb = b;
	return strcmp((*sympa)->label, (*sympb)->label);
}

static int symbolp_bsearch_compare(const void *key, const void *elt)
{
	const char *name = key;
	const struct ksplice_symbol *const *symp = elt;
	const struct ksplice_symbol *sym = *symp;
	if (sym->name == NULL)
		return 1;
	return strcmp(name, sym->name);
}

static abort_t add_matching_values(struct ksplice_lookup *lookup,
				   const char *sym_name, unsigned long sym_val)
{
	struct ksplice_symbol **symp;
	abort_t ret;

	symp = bsearch(sym_name, lookup->arr, lookup->size,
		       sizeof(*lookup->arr), symbolp_bsearch_compare);
	if (symp == NULL)
		return OK;

	while (symp > lookup->arr &&
	       symbolp_bsearch_compare(sym_name, symp - 1) == 0)
		symp--;

	for (; symp < lookup->arr + lookup->size; symp++) {
		struct ksplice_symbol *sym = *symp;
		if (sym->name == NULL || strcmp(sym_name, sym->name) != 0)
			break;
		ret = add_candidate_val(lookup->change,
					sym->candidate_vals, sym_val);
		if (ret != OK)
			return ret;
	}
	return OK;
}

#ifdef CONFIG_KALLSYMS
static int add_kallsyms_values(void *data, const char *name,
			       struct module *owner, unsigned long val)
{
	struct ksplice_lookup *lookup = data;
	if (owner == lookup->change->new_code_mod ||
	    !patches_module(owner, lookup->change->target))
		return (__force int)OK;
	return (__force int)add_matching_values(lookup, name, val);
}
#endif /* CONFIG_KALLSYMS */

static bool add_export_values(const struct symsearch *syms,
			      struct module *owner,
			      unsigned int symnum, void *data)
{
	struct ksplice_lookup *lookup = data;
	abort_t ret;

	ret = add_matching_values(lookup, syms->start[symnum].name,
				  syms->start[symnum].value);
	if (ret != OK) {
		lookup->ret = ret;
		return true;
	}
	return false;
}

static bool add_export_values_section(const struct symsearch *syms,
		struct module *owner, void *data)
{
	unsigned int i;

	for (i = 0; i < syms->stop - syms->start; i++)
		if (add_export_values(syms, owner, i, data))
			return true;

	return false;
}

static void cleanup_symbol_arrays(struct ksplice_mod_change *change)
{
	struct ksplice_symbol *sym;
	for (sym = change->new_code.symbols; sym < change->new_code.symbols_end;
	     sym++) {
		if (sym->candidate_vals != NULL) {
			clear_list(sym->candidate_vals, struct candidate_val,
				   list);
			kfree(sym->candidate_vals);
			sym->candidate_vals = NULL;
		}
	}
	for (sym = change->old_code.symbols; sym < change->old_code.symbols_end;
	     sym++) {
		if (sym->candidate_vals != NULL) {
			clear_list(sym->candidate_vals, struct candidate_val,
				   list);
			kfree(sym->candidate_vals);
			sym->candidate_vals = NULL;
		}
	}
}

/*
 * The new_code and old_code modules each have their own independent
 * ksplice_symbol structures.  uniquify_symbols unifies these separate
 * pieces of kernel symbol information by replacing all references to
 * the old_code copy of symbols with references to the new_code copy.
 */
static abort_t uniquify_symbols(struct ksplice_mod_change *change)
{
	struct ksplice_reloc *r;
	struct ksplice_section *s;
	struct ksplice_symbol *sym, **sym_arr, **symp;
	size_t size = change->new_code.symbols_end - change->new_code.symbols;

	if (size == 0)
		return OK;

	sym_arr = vmalloc(sizeof(*sym_arr) * size);
	if (sym_arr == NULL)
		return OUT_OF_MEMORY;

	for (symp = sym_arr, sym = change->new_code.symbols;
	     symp < sym_arr + size && sym < change->new_code.symbols_end;
	     sym++, symp++)
		*symp = sym;

	sort(sym_arr, size, sizeof(*sym_arr), compare_symbolp_labels, NULL);

	for (r = change->old_code.relocs; r < change->old_code.relocs_end;
	     r++) {
		symp = bsearch(&r->symbol, sym_arr, size, sizeof(*sym_arr),
			       compare_symbolp_labels);
		if (symp != NULL) {
			if ((*symp)->name == NULL)
				(*symp)->name = r->symbol->name;
			r->symbol = *symp;
		}
	}

	for (s = change->old_code.sections; s < change->old_code.sections_end;
	     s++) {
		symp = bsearch(&s->symbol, sym_arr, size, sizeof(*sym_arr),
			       compare_symbolp_labels);
		if (symp != NULL) {
			if ((*symp)->name == NULL)
				(*symp)->name = s->symbol->name;
			s->symbol = *symp;
		}
	}

	vfree(sym_arr);
	return OK;
}

/*
 * Initialize the ksplice_symbol structures in the given array using
 * the kallsyms and exported symbol tables.
 */
static abort_t init_symbol_array(struct ksplice_mod_change *change,
				 struct ksplice_symbol *start,
				 struct ksplice_symbol *end)
{
	struct ksplice_symbol *sym, **sym_arr, **symp;
	struct ksplice_lookup lookup;
	size_t size = end - start;
	abort_t ret;

	if (size == 0)
		return OK;

	for (sym = start; sym < end; sym++) {
		if (strstarts(sym->label, "__ksymtab")) {
			const struct kernel_symbol *ksym;
			const char *colon = strchr(sym->label, ':');
			const char *name = colon + 1;
			if (colon == NULL)
				continue;
			ksym = find_symbol(name, NULL, NULL, true, false);
			if (ksym == NULL) {
				ksdebug(change, "Could not find kernel_symbol "
					"structure for %s\n", name);
				continue;
			}
			sym->value = (unsigned long)ksym;
			sym->candidate_vals = NULL;
			continue;
		}

		sym->candidate_vals = kmalloc(sizeof(*sym->candidate_vals),
					      GFP_KERNEL);
		if (sym->candidate_vals == NULL)
			return OUT_OF_MEMORY;
		INIT_LIST_HEAD(sym->candidate_vals);
		sym->value = 0;
	}

	sym_arr = vmalloc(sizeof(*sym_arr) * size);
	if (sym_arr == NULL)
		return OUT_OF_MEMORY;

	for (symp = sym_arr, sym = start; symp < sym_arr + size && sym < end;
	     sym++, symp++)
		*symp = sym;

	sort(sym_arr, size, sizeof(*sym_arr), compare_symbolp_names, NULL);

	lookup.change = change;
	lookup.arr = sym_arr;
	lookup.size = size;
	lookup.ret = OK;

	each_symbol_section(add_export_values_section, &lookup);
	ret = lookup.ret;
#ifdef CONFIG_KALLSYMS
	if (ret == OK)
		ret = (__force abort_t)
		    kallsyms_on_each_symbol(add_kallsyms_values, &lookup);
#endif /* CONFIG_KALLSYMS */
	vfree(sym_arr);
	return ret;
}

/*
 * Prepare the change's ksplice_symbol structures for run-pre matching
 *
 * noinline to prevent garbage on the stack from confusing check_stack
 */
static noinline abort_t init_symbol_arrays(struct ksplice_mod_change *change)
{
	abort_t ret;

	ret = uniquify_symbols(change);
	if (ret != OK)
		return ret;

	ret = init_symbol_array(change, change->old_code.symbols,
				change->old_code.symbols_end);
	if (ret != OK)
		return ret;

	ret = init_symbol_array(change, change->new_code.symbols,
				change->new_code.symbols_end);
	if (ret != OK)
		return ret;

	return OK;
}

/* noinline to prevent garbage on the stack from confusing check_stack */
static noinline abort_t prepare_change(struct ksplice_mod_change *change)
{
	abort_t ret;

	ksdebug(change, "Preparing and checking %s\n", change->name);
	ret = match_change_sections(change, false);
	if (ret == NO_MATCH) {
		/* It is possible that by using relocations from .data sections
		 * we can successfully run-pre match the rest of the sections.
		 * To avoid using any symbols obtained from .data sections
		 * (which may be unreliable) in the post code, we first prepare
		 * the post code and then try to run-pre match the remaining
		 * sections with the help of .data sections.
		 */
		ksdebug(change, "Continuing without some sections; we might "
			"find them later.\n");
		ret = finalize_change(change);
		if (ret != OK) {
			ksdebug(change, "Aborted.  Unable to continue without "
				"the unmatched sections.\n");
			return ret;
		}

		ksdebug(change, "run-pre: Considering .data sections to find "
			"the unmatched sections\n");
		ret = match_change_sections(change, true);
		if (ret != OK)
			return ret;

		ksdebug(change, "run-pre: Found all previously unmatched "
			"sections\n");
		return OK;
	} else if (ret != OK) {
		return ret;
	}

	return finalize_change(change);
}

/*
 * Finish preparing the change for insertion into the kernel.
 * Afterwards, the replacement code should be ready to run and the
 * ksplice_patches should all be ready for trampoline insertion.
 */
static abort_t finalize_change(struct ksplice_mod_change *change)
{
	abort_t ret;
	ret = apply_relocs(change, change->new_code.relocs,
			   change->new_code.relocs_end);
	if (ret != OK)
		return ret;

	ret = finalize_patches(change);
	if (ret != OK)
		return ret;

	return OK;
}

static abort_t finalize_patches(struct ksplice_mod_change *change)
{
	struct ksplice_patch *p;
	struct safety_record *rec;
	abort_t ret;

	for (p = change->patches; p < change->patches_end; p++) {
		bool found = false;
		list_for_each_entry(rec, &change->safety_records, list) {
			if (rec->addr <= p->oldaddr &&
			    p->oldaddr < rec->addr + rec->size) {
				found = true;
				break;
			}
		}
		if (!found && p->type != KSPLICE_PATCH_EXPORT) {
			const struct ksplice_reloc *r = patch_reloc(change, p);
			if (r == NULL) {
				ksdebug(change, "A patch with no reloc at its "
					"oldaddr has no safety record\n");
				return NO_MATCH;
			}
			ksdebug(change, "No safety record for patch with "
				"oldaddr %s+%lx\n", r->symbol->label,
				r->target_addend);
			return NO_MATCH;
		}

		if (p->type == KSPLICE_PATCH_TEXT) {
			ret = prepare_trampoline(change, p);
			if (ret != OK)
				return ret;
		}

		if (found && rec->addr + rec->size < p->oldaddr + p->size) {
			ksdebug(change, "Safety record %s is too short for "
				"patch\n", rec->label);
			return UNEXPECTED;
		}

		if (p->type == KSPLICE_PATCH_TEXT) {
			if (p->repladdr == 0)
				p->repladdr = (unsigned long)ksplice_deleted;
		}
	}

	for (p = change->patches; p < change->patches_end; p++) {
		struct ksplice_patch *q;
		for (q = change->patches; q < change->patches_end; q++) {
			if (p != q && p->oldaddr <= q->oldaddr &&
			    p->oldaddr + p->size > q->oldaddr) {
				ksdebug(change, "Overlapping oldaddrs "
					"for patches\n");
				return UNEXPECTED;
			}
		}
	}

	return OK;
}

/* noinline to prevent garbage on the stack from confusing check_stack */
static noinline abort_t map_trampoline_pages(struct update *update)
{
	struct ksplice_mod_change *change;
	list_for_each_entry(change, &update->changes, list) {
		struct ksplice_patch *p;
		for (p = change->patches; p < change->patches_end; p++) {
			p->vaddr = map_writable((void *)p->oldaddr, p->size);
			if (p->vaddr == NULL) {
				ksdebug(change,
					"Unable to map oldaddr read/write\n");
				unmap_trampoline_pages(update);
				return UNEXPECTED;
			}
		}
	}
	return OK;
}

static void unmap_trampoline_pages(struct update *update)
{
	struct ksplice_mod_change *change;
	list_for_each_entry(change, &update->changes, list) {
		struct ksplice_patch *p;
		for (p = change->patches; p < change->patches_end; p++) {
			vunmap((void *)((unsigned long)p->vaddr & PAGE_MASK));
			p->vaddr = NULL;
		}
	}
}

/*
 * map_writable creates a shadow page mapping of the range
 * [addr, addr + len) so that we can write to code mapped read-only.
 *
 * It is similar to a generalized version of x86's text_poke.  But
 * because one cannot use vmalloc/vfree() inside stop_machine, we use
 * map_writable to map the pages before stop_machine, then use the
 * mapping inside stop_machine, and unmap the pages afterwards.
 */
static void *map_writable(void *addr, size_t len)
{
	void *vaddr;
	int nr_pages = DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE);
	struct page **pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
	void *page_addr = (void *)((unsigned long)addr & PAGE_MASK);
	int i;

	if (pages == NULL)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		if (__module_address((unsigned long)page_addr) == NULL) {
			pages[i] = virt_to_page(page_addr);
			WARN_ON(!PageReserved(pages[i]));
		} else {
			pages[i] = vmalloc_to_page(page_addr);
		}
		if (pages[i] == NULL) {
			kfree(pages);
			return NULL;
		}
		page_addr += PAGE_SIZE;
	}
	vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
	kfree(pages);
	if (vaddr == NULL)
		return NULL;
	return vaddr + offset_in_page(addr);
}

/*
 * Ksplice adds a dependency on any symbol address used to resolve
 * relocations in the new_code module.
 *
 * Be careful to follow_trampolines so that we always depend on the
 * latest version of the target function, since that's the code that
 * will run if we call addr.
 */
static abort_t add_dependency_on_address(struct ksplice_mod_change *change,
					 unsigned long addr)
{
	struct ksplice_mod_change *c;
	struct module *m =
	    __module_text_address(follow_trampolines(change, addr));
	if (m == NULL)
		return OK;
	list_for_each_entry(c, &change->update->changes, list) {
		if (m == c->new_code_mod)
			return OK;
	}
	if (ref_module(change->new_code_mod, m))
		return MODULE_BUSY;
	return OK;
}

static abort_t apply_relocs(struct ksplice_mod_change *change,
			    const struct ksplice_reloc *relocs,
			    const struct ksplice_reloc *relocs_end)
{
	const struct ksplice_reloc *r;
	for (r = relocs; r < relocs_end; r++) {
		abort_t ret = apply_reloc(change, r);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static abort_t apply_reloc(struct ksplice_mod_change *change,
			   const struct ksplice_reloc *r)
{
	switch (r->howto->type) {
	case KSPLICE_HOWTO_RELOC:
	case KSPLICE_HOWTO_RELOC_PATCH:
		return apply_howto_reloc(change, r);
	case KSPLICE_HOWTO_DATE:
	case KSPLICE_HOWTO_TIME:
		return apply_howto_date(change, r);
	default:
		ksdebug(change, "Unexpected howto type %d\n", r->howto->type);
		return UNEXPECTED;
	}
}

/*
 * Applies a relocation.  Aborts if the symbol referenced in it has
 * not been uniquely resolved.
 */
static abort_t apply_howto_reloc(struct ksplice_mod_change *change,
				 const struct ksplice_reloc *r)
{
	abort_t ret;
	int canary_ret;
	unsigned long sym_addr;
	LIST_HEAD(vals);

	canary_ret = contains_canary(change, r->blank_addr, r->howto);
	if (canary_ret < 0)
		return UNEXPECTED;
	if (canary_ret == 0) {
		ksdebug(change, "reloc: skipped %lx to %s+%lx (altinstr)\n",
			r->blank_addr, r->symbol->label, r->target_addend);
		return OK;
	}

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped) {
		ret = add_system_map_candidates(change,
						change->new_code.system_map,
						change->new_code.system_map_end,
						r->symbol->label, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
	}
#endif /* KSPLICE_STANDALONE */
	ret = lookup_symbol(change, r->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
	/*
	 * Relocations for the oldaddr fields of patches must have
	 * been resolved via run-pre matching.
	 */
	if (!singular(&vals) || (r->symbol->candidate_vals != NULL &&
				 r->howto->type == KSPLICE_HOWTO_RELOC_PATCH)) {
		release_vals(&vals);
		ksdebug(change, "Failed to find %s for reloc\n",
			r->symbol->label);
		return FAILED_TO_FIND;
	}
	sym_addr = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	ret = write_reloc_value(change, r, r->blank_addr,
				r->howto->pcrel ? sym_addr - r->blank_addr :
				sym_addr);
	if (ret != OK)
		return ret;

	ksdebug(change, "reloc: %lx to %s+%lx (S=%lx ", r->blank_addr,
		r->symbol->label, r->target_addend, sym_addr);
	switch (r->howto->size) {
	case 1:
		ksdebug(change, "aft=%02x)\n", *(uint8_t *)r->blank_addr);
		break;
	case 2:
		ksdebug(change, "aft=%04x)\n", *(uint16_t *)r->blank_addr);
		break;
	case 4:
		ksdebug(change, "aft=%08x)\n", *(uint32_t *)r->blank_addr);
		break;
#if BITS_PER_LONG >= 64
	case 8:
		ksdebug(change, "aft=%016llx)\n", *(uint64_t *)r->blank_addr);
		break;
#endif /* BITS_PER_LONG */
	default:
		ksdebug(change, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}
#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	/*
	 * Create labelvals so that we can verify our choices in the
	 * second round of run-pre matching that considers data sections.
	 */
	ret = create_labelval(change, r->symbol, sym_addr, VAL);
	if (ret != OK)
		return ret;

	return add_dependency_on_address(change, sym_addr);
}

/*
 * Date relocations are created wherever __DATE__ or __TIME__ is used
 * in the kernel; we resolve them by simply copying in the date/time
 * obtained from run-pre matching the relevant compilation unit.
 */
static abort_t apply_howto_date(struct ksplice_mod_change *change,
				const struct ksplice_reloc *r)
{
	if (r->symbol->candidate_vals != NULL) {
		ksdebug(change, "Failed to find %s for date\n",
			r->symbol->label);
		return FAILED_TO_FIND;
	}
	memcpy((unsigned char *)r->blank_addr,
	       (const unsigned char *)r->symbol->value, r->howto->size);
	return OK;
}

/*
 * Given a relocation and its run address, compute the address of the
 * symbol the relocation referenced, and store it in *valp.
 */
static abort_t read_reloc_value(struct ksplice_mod_change *change,
				const struct ksplice_reloc *r,
				unsigned long addr, unsigned long *valp)
{
	unsigned char bytes[sizeof(long)];
	unsigned long val;
	const struct ksplice_reloc_howto *howto = r->howto;

	if (howto->size <= 0 || howto->size > sizeof(long)) {
		ksdebug(change, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}

	if (probe_kernel_read(bytes, (void *)addr, howto->size) == -EFAULT)
		return NO_MATCH;

	switch (howto->size) {
	case 1:
		val = *(uint8_t *)bytes;
		break;
	case 2:
		val = *(uint16_t *)bytes;
		break;
	case 4:
		val = *(uint32_t *)bytes;
		break;
#if BITS_PER_LONG >= 64
	case 8:
		val = *(uint64_t *)bytes;
		break;
#endif /* BITS_PER_LONG */
	default:
		ksdebug(change, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}

	val &= howto->dst_mask;
	if (howto->signed_addend)
		val |= -(val & (howto->dst_mask & ~(howto->dst_mask >> 1)));
	val <<= howto->rightshift;
	val -= r->insn_addend + r->target_addend;
	*valp = val;
	return OK;
}

/*
 * Given a relocation, the address of its storage unit, and the
 * address of the symbol the relocation references, write the
 * relocation's final value into the storage unit.
 */
static abort_t write_reloc_value(struct ksplice_mod_change *change,
				 const struct ksplice_reloc *r,
				 unsigned long addr, unsigned long sym_addr)
{
	unsigned long val = sym_addr + r->target_addend + r->insn_addend;
	const struct ksplice_reloc_howto *howto = r->howto;
	val >>= howto->rightshift;
	switch (howto->size) {
	case 1:
		*(uint8_t *)addr = (*(uint8_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
	case 2:
		*(uint16_t *)addr = (*(uint16_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
	case 4:
		*(uint32_t *)addr = (*(uint32_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
#if BITS_PER_LONG >= 64
	case 8:
		*(uint64_t *)addr = (*(uint64_t *)addr & ~howto->dst_mask) |
		    (val & howto->dst_mask);
		break;
#endif /* BITS_PER_LONG */
	default:
		ksdebug(change, "Aborted.  Invalid relocation size.\n");
		return UNEXPECTED;
	}

	if (read_reloc_value(change, r, addr, &val) != OK || val != sym_addr) {
		ksdebug(change, "Aborted.  Relocation overflow.\n");
		return UNEXPECTED;
	}

	return OK;
}

static abort_t create_module_list_entry(struct ksplice_mod_change *change,
					bool to_be_applied)
{
	struct ksplice_module_list_entry *entry =
	    kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return OUT_OF_MEMORY;
	entry->new_code_mod_name =
	    kstrdup(change->new_code_mod->name, GFP_KERNEL);
	if (entry->new_code_mod_name == NULL) {
		kfree(entry);
		return OUT_OF_MEMORY;
	}
	entry->target_mod_name = kstrdup(change->target_name, GFP_KERNEL);
	if (entry->target_mod_name == NULL) {
		kfree(entry->new_code_mod_name);
		kfree(entry);
		return OUT_OF_MEMORY;
	}
	/* The update's kid is guaranteed to outlast the module_list_entry */
	entry->kid = change->update->kid;
	entry->applied = to_be_applied;
	list_add(&entry->update_list, &change->update->ksplice_module_list);
	return OK;
}

static void cleanup_module_list_entries(struct update *update)
{
	struct ksplice_module_list_entry *entry;
	list_for_each_entry(entry, &update->ksplice_module_list, update_list) {
		kfree(entry->target_mod_name);
		kfree(entry->new_code_mod_name);
	}
	clear_list(&update->ksplice_module_list,
		   struct ksplice_module_list_entry, update_list);
}

/* Replacement address used for functions deleted by the patch */
static void __attribute__((noreturn)) ksplice_deleted(void)
{
	printk(KERN_CRIT "Called a kernel function deleted by Ksplice!\n");
	BUG();
}

/* Floodfill to run-pre match the sections within a change. */
static abort_t match_change_sections(struct ksplice_mod_change *change,
				   bool consider_data_sections)
{
	struct ksplice_section *sect;
	abort_t ret;
	int remaining = 0;
	bool progress;

	for (sect = change->old_code.sections;
	     sect < change->old_code.sections_end; sect++) {
		if (((sect->flags & KSPLICE_SECTION_DATA) == 0 ||
		     (sect->flags & KSPLICE_SECTION_MATCH_DATA_EARLY) != 0) &&
		    (sect->flags & KSPLICE_SECTION_STRING) == 0 &&
		    (sect->flags & KSPLICE_SECTION_MATCHED) == 0)
			remaining++;
	}

	while (remaining > 0) {
		progress = false;
		for (sect = change->old_code.sections;
		     sect < change->old_code.sections_end; sect++) {
			if ((sect->flags & KSPLICE_SECTION_MATCHED) != 0)
				continue;
			if ((!consider_data_sections &&
			     (sect->flags & KSPLICE_SECTION_DATA) != 0 &&
			     (sect->flags & KSPLICE_SECTION_MATCH_DATA_EARLY) == 0) ||
			    (sect->flags & KSPLICE_SECTION_STRING) != 0)
				continue;
			ret = find_section(change, sect);
			if (ret == OK) {
				sect->flags |= KSPLICE_SECTION_MATCHED;
				if ((sect->flags & KSPLICE_SECTION_DATA) == 0 ||
				    (sect->flags & KSPLICE_SECTION_MATCH_DATA_EARLY) != 0)
					remaining--;
				progress = true;
			} else if (ret != NO_MATCH) {
				return ret;
			}
		}

		if (progress)
			continue;

		for (sect = change->old_code.sections;
		     sect < change->old_code.sections_end; sect++) {
			if ((sect->flags & KSPLICE_SECTION_MATCHED) != 0 ||
			    (sect->flags & KSPLICE_SECTION_STRING) != 0)
				continue;
			ksdebug(change, "run-pre: could not match %s "
				"section %s\n",
				(sect->flags & KSPLICE_SECTION_DATA) != 0 ?
				"data" :
				(sect->flags & KSPLICE_SECTION_RODATA) != 0 ?
				"rodata" : "text", sect->symbol->label);
		}
		ksdebug(change, "Aborted.  run-pre: could not match some "
			"sections.\n");
		return NO_MATCH;
	}
	return OK;
}

/*
 * Search for the section in the running kernel.  Returns OK if and
 * only if it finds precisely one address in the kernel matching the
 * section.
 */
static abort_t find_section(struct ksplice_mod_change *change,
			    struct ksplice_section *sect)
{
	int i;
	abort_t ret;
	unsigned long run_addr;
	LIST_HEAD(vals);
	struct candidate_val *v, *n;

#ifdef KSPLICE_STANDALONE
	ret = add_system_map_candidates(change, change->old_code.system_map,
					change->old_code.system_map_end,
					sect->symbol->label, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}
#endif /* KSPLICE_STANDALONE */
	ret = lookup_symbol(change, sect->symbol, &vals);
	if (ret != OK) {
		release_vals(&vals);
		return ret;
	}

	ksdebug(change, "run-pre: starting sect search for %s\n",
		sect->symbol->label);

	list_for_each_entry_safe(v, n, &vals, list) {
		run_addr = v->val;

		yield();
		ret = try_addr(change, sect, run_addr, NULL, RUN_PRE_INITIAL);
		if (ret == NO_MATCH) {
			list_del(&v->list);
			kfree(v);
		} else if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
	}

#if defined(KSPLICE_STANDALONE) && !defined(CONFIG_KALLSYMS)
	if (list_empty(&vals) && (sect->flags & KSPLICE_SECTION_DATA) == 0) {
		ret = brute_search_all(change, sect, &vals);
		if (ret != OK) {
			release_vals(&vals);
			return ret;
		}
		/*
		 * Make sure run-pre matching output is displayed if
		 * brute_search succeeds.
		 */
		if (singular(&vals)) {
			run_addr = list_entry(vals.next, struct candidate_val,
					      list)->val;
			ret = try_addr(change, sect, run_addr, NULL,
				       RUN_PRE_INITIAL);
			if (ret != OK) {
				ksdebug(change, "run-pre: Debug run failed for "
					"sect %s:\n", sect->symbol->label);
				release_vals(&vals);
				return ret;
			}
		}
	}
#endif /* KSPLICE_STANDALONE && !CONFIG_KALLSYMS */

	if (singular(&vals)) {
		LIST_HEAD(safety_records);
		run_addr = list_entry(vals.next, struct candidate_val,
				      list)->val;
		ret = try_addr(change, sect, run_addr, &safety_records,
			       RUN_PRE_FINAL);
		release_vals(&vals);
		if (ret != OK) {
			clear_list(&safety_records, struct safety_record, list);
			ksdebug(change, "run-pre: Final run failed for sect "
				"%s:\n", sect->symbol->label);
		} else {
			list_splice(&safety_records, &change->safety_records);
		}
		return ret;
	} else if (!list_empty(&vals)) {
		struct candidate_val *val;
		ksdebug(change, "run-pre: multiple candidates for sect %s:\n",
			sect->symbol->label);
		i = 0;
		list_for_each_entry(val, &vals, list) {
			i++;
			ksdebug(change, "%lx\n", val->val);
			if (i > 5) {
				ksdebug(change, "...\n");
				break;
			}
		}
		release_vals(&vals);
		return NO_MATCH;
	}
	release_vals(&vals);
	return NO_MATCH;
}

/*
 * try_addr is the the interface to run-pre matching.  Its primary
 * purpose is to manage debugging information for run-pre matching;
 * all the hard work is in run_pre_cmp.
 */
static abort_t try_addr(struct ksplice_mod_change *change,
			struct ksplice_section *sect,
			unsigned long run_addr,
			struct list_head *safety_records,
			enum run_pre_mode mode)
{
	abort_t ret;
	const struct module *run_module = __module_address(run_addr);

	if (run_module == change->new_code_mod) {
		ksdebug(change, "run-pre: unexpected address %lx in new_code "
			"module %s for sect %s\n", run_addr, run_module->name,
			sect->symbol->label);
		return UNEXPECTED;
	}
	if (!patches_module(run_module, change->target)) {
		ksdebug(change, "run-pre: ignoring address %lx in other module "
			"%s for sect %s\n", run_addr, run_module == NULL ?
			"vmlinux" : run_module->name, sect->symbol->label);
		return NO_MATCH;
	}

	ret = create_labelval(change, sect->symbol, run_addr, TEMP);
	if (ret != OK)
		return ret;

#ifdef CONFIG_FUNCTION_DATA_SECTIONS
	ret = run_pre_cmp(change, sect, run_addr, safety_records, mode);
#else /* !CONFIG_FUNCTION_DATA_SECTIONS */
	if ((sect->flags & KSPLICE_SECTION_TEXT) != 0)
		ret = arch_run_pre_cmp(change, sect, run_addr, safety_records,
				       mode);
	else
		ret = run_pre_cmp(change, sect, run_addr, safety_records, mode);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
	if (ret == NO_MATCH && mode != RUN_PRE_FINAL) {
		set_temp_labelvals(change, NOVAL);
		ksdebug(change, "run-pre: %s sect %s does not match (r_a=%lx "
			"p_a=%lx s=%lx)\n",
			(sect->flags & KSPLICE_SECTION_RODATA) != 0 ? "rodata" :
			(sect->flags & KSPLICE_SECTION_DATA) != 0 ? "data" :
			"text", sect->symbol->label, run_addr, sect->address,
			sect->size);
		ksdebug(change, "run-pre: ");
		if (change->update->debug >= 1) {
#ifdef CONFIG_FUNCTION_DATA_SECTIONS
			ret = run_pre_cmp(change, sect, run_addr,
					  safety_records, RUN_PRE_DEBUG);
#else /* !CONFIG_FUNCTION_DATA_SECTIONS */
			if ((sect->flags & KSPLICE_SECTION_TEXT) != 0)
				ret = arch_run_pre_cmp(change, sect, run_addr,
						       safety_records,
						       RUN_PRE_DEBUG);
			else
				ret = run_pre_cmp(change, sect, run_addr,
						  safety_records,
						  RUN_PRE_DEBUG);
#endif /* CONFIG_FUNCTION_DATA_SECTIONS */
			set_temp_labelvals(change, NOVAL);
		}
		ksdebug(change, "\n");
		return ret;
	} else if (ret != OK) {
		set_temp_labelvals(change, NOVAL);
		return ret;
	}

	if (mode != RUN_PRE_FINAL) {
		set_temp_labelvals(change, NOVAL);
		ksdebug(change, "run-pre: candidate for sect %s=%lx\n",
			sect->symbol->label, run_addr);
		return OK;
	}

	set_temp_labelvals(change, VAL);
	ksdebug(change, "run-pre: found sect %s=%lx\n", sect->symbol->label,
		run_addr);
	return OK;
}

/*
 * run_pre_cmp is the primary run-pre matching function; it determines
 * whether the given ksplice_section matches the code or data in the
 * running kernel starting at run_addr.
 *
 * If run_pre_mode is RUN_PRE_FINAL, a safety record for the matched
 * section is created.
 *
 * The run_pre_mode is also used to determine what debugging
 * information to display.
 */
static abort_t run_pre_cmp(struct ksplice_mod_change *change,
			   const struct ksplice_section *sect,
			   unsigned long run_addr,
			   struct list_head *safety_records,
			   enum run_pre_mode mode)
{
	int matched = 0;
	abort_t ret;
	const struct ksplice_reloc *r, *finger;
	const unsigned char *pre, *run, *pre_start, *run_start;
	unsigned char runval;

	pre_start = (const unsigned char *)sect->address;
	run_start = (const unsigned char *)run_addr;

	finger = init_reloc_search(change, sect);

	pre = pre_start;
	run = run_start;
	while (pre < pre_start + sect->size) {
		unsigned long offset = pre - pre_start;
		ret = lookup_reloc(change, &finger, (unsigned long)pre, &r);
		if (ret == OK) {
			ret = handle_reloc(change, sect, r, (unsigned long)run,
					   mode);
			if (ret != OK) {
				if (mode == RUN_PRE_INITIAL)
					ksdebug(change, "reloc in sect does "
						"not match after %lx/%lx "
						"bytes\n", offset, sect->size);
				return ret;
			}
			if (mode == RUN_PRE_DEBUG)
				print_bytes(change, run, r->howto->size, pre,
					    r->howto->size);
			pre += r->howto->size;
			run += r->howto->size;
			finger++;
			continue;
		} else if (ret != NO_MATCH) {
			return ret;
		}

		if ((sect->flags & KSPLICE_SECTION_TEXT) != 0) {
			ret = handle_paravirt(change, (unsigned long)pre,
					      (unsigned long)run, &matched);
			if (ret != OK)
				return ret;
			if (matched != 0) {
				if (mode == RUN_PRE_DEBUG)
					print_bytes(change, run, matched, pre,
						    matched);
				pre += matched;
				run += matched;
				continue;
			}
		}

		if (probe_kernel_read(&runval, (void *)run, 1) == -EFAULT) {
			if (mode == RUN_PRE_INITIAL)
				ksdebug(change, "sect unmapped after %lx/%lx "
					"bytes\n", offset, sect->size);
			return NO_MATCH;
		}

		if (runval != *pre &&
		    (sect->flags & KSPLICE_SECTION_DATA) == 0) {
			if (mode == RUN_PRE_INITIAL)
				ksdebug(change, "sect does not match after "
					"%lx/%lx bytes\n", offset, sect->size);
			if (mode == RUN_PRE_DEBUG) {
				print_bytes(change, run, 1, pre, 1);
				ksdebug(change, "[p_o=%lx] ! ", offset);
				print_bytes(change, run + 1, 2, pre + 1, 2);
			}
			return NO_MATCH;
		}
		if (mode == RUN_PRE_DEBUG)
			print_bytes(change, run, 1, pre, 1);
		pre++;
		run++;
	}
	return create_safety_record(change, sect, safety_records, run_addr,
				    run - run_start);
}

static void print_bytes(struct ksplice_mod_change *change,
			const unsigned char *run, int runc,
			const unsigned char *pre, int prec)
{
	int o;
	int matched = min(runc, prec);
	for (o = 0; o < matched; o++) {
		if (run[o] == pre[o])
			ksdebug(change, "%02x ", run[o]);
		else
			ksdebug(change, "%02x/%02x ", run[o], pre[o]);
	}
	for (o = matched; o < runc; o++)
		ksdebug(change, "%02x/ ", run[o]);
	for (o = matched; o < prec; o++)
		ksdebug(change, "/%02x ", pre[o]);
}

#if defined(KSPLICE_STANDALONE) && !defined(CONFIG_KALLSYMS)
static abort_t brute_search(struct ksplice_mod_change *change,
			    struct ksplice_section *sect,
			    const void *start, unsigned long len,
			    struct list_head *vals)
{
	unsigned long addr;
	char run, pre;
	abort_t ret;

	for (addr = (unsigned long)start; addr < (unsigned long)start + len;
	     addr++) {
		if (addr % 100000 == 0)
			yield();

		if (probe_kernel_read(&run, (void *)addr, 1) == -EFAULT)
			return OK;

		pre = *(const unsigned char *)(sect->address);

		if (run != pre)
			continue;

		ret = try_addr(change, sect, addr, NULL, RUN_PRE_INITIAL);
		if (ret == OK) {
			ret = add_candidate_val(change, vals, addr);
			if (ret != OK)
				return ret;
		} else if (ret != NO_MATCH) {
			return ret;
		}
	}

	return OK;
}

extern struct list_head modules;
EXTRACT_SYMBOL(modules);
EXTRACT_SYMBOL(init_mm);

static abort_t brute_search_all(struct ksplice_mod_change *change,
				struct ksplice_section *sect,
				struct list_head *vals)
{
	struct module *m;
	abort_t ret = OK;
	int saved_debug;

	ksdebug(change, "brute_search: searching for %s\n",
		sect->symbol->label);
	saved_debug = change->update->debug;
	change->update->debug = 0;

	list_for_each_entry(m, &modules, list) {
		if (!patches_module(m, change->target) ||
		    m == change->new_code_mod)
			continue;
		ret = brute_search(change, sect, m->module_core, m->core_size,
				   vals);
		if (ret != OK)
			goto out;
		ret = brute_search(change, sect, m->module_init, m->init_size,
				   vals);
		if (ret != OK)
			goto out;
	}

	ret = brute_search(change, sect, (const void *)init_mm.start_code,
			   init_mm.end_code - init_mm.start_code, vals);

out:
	change->update->debug = saved_debug;
	return ret;
}
#endif /* KSPLICE_STANDALONE && !CONFIG_KALLSYMS */

struct addr_range {
	unsigned long address;
	unsigned long size;
};

static int reloc_bsearch_compare(const void *key, const void *elt)
{
	const struct addr_range *range = key;
	const struct ksplice_reloc *r = elt;
	if (range->address + range->size <= r->blank_addr)
		return -1;
	if (range->address > r->blank_addr)
		return 1;
	return 0;
}

static const struct ksplice_reloc *find_reloc(const struct ksplice_reloc *start,
					      const struct ksplice_reloc *end,
					      unsigned long address,
					      unsigned long size)
{
	const struct ksplice_reloc *r;
	struct addr_range range = { address, size };
	r = bsearch((void *)&range, start, end - start, sizeof(*r),
		    reloc_bsearch_compare);
	if (r == NULL)
		return NULL;
	while (r > start && (r - 1)->blank_addr >= address)
		r--;
	return r;
}

static const struct ksplice_reloc *
init_reloc_search(struct ksplice_mod_change *change,
		  const struct ksplice_section *sect)
{
	const struct ksplice_reloc *r;
	r = find_reloc(change->old_code.relocs, change->old_code.relocs_end,
		       sect->address, sect->size);
	if (r == NULL)
		return change->old_code.relocs_end;
	return r;
}

/*
 * lookup_reloc implements an amortized O(1) lookup for the next
 * old_code relocation.  It must be called with a strictly increasing
 * sequence of addresses.
 *
 * The fingerp is private data for lookup_reloc, and needs to have
 * been initialized as a pointer to the result of find_reloc (or
 * init_reloc_search).
 */
static abort_t lookup_reloc(struct ksplice_mod_change *change,
			    const struct ksplice_reloc **fingerp,
			    unsigned long addr,
			    const struct ksplice_reloc **relocp)
{
	const struct ksplice_reloc *r = *fingerp;
	int canary_ret;

	while (r < change->old_code.relocs_end &&
	       addr >= r->blank_addr + r->howto->size &&
	       !(addr == r->blank_addr && r->howto->size == 0))
		r++;
	*fingerp = r;
	if (r == change->old_code.relocs_end)
		return NO_MATCH;
	if (addr < r->blank_addr)
		return NO_MATCH;
	*relocp = r;
	if (r->howto->type != KSPLICE_HOWTO_RELOC)
		return OK;

	canary_ret = contains_canary(change, r->blank_addr, r->howto);
	if (canary_ret < 0)
		return UNEXPECTED;
	if (canary_ret == 0) {
		ksdebug(change, "run-pre: reloc skipped at p_a=%lx to %s+%lx "
			"(altinstr)\n", r->blank_addr, r->symbol->label,
			r->target_addend);
		return NO_MATCH;
	}
	if (addr != r->blank_addr) {
		ksdebug(change, "Invalid nonzero relocation offset\n");
		return UNEXPECTED;
	}
	return OK;
}

static abort_t handle_howto_symbol(struct ksplice_mod_change *change,
				   const struct ksplice_reloc *r,
				   unsigned long run_addr,
				   enum run_pre_mode mode)
{
	if (mode == RUN_PRE_INITIAL)
		ksdebug(change, "run-pre: symbol %s at %lx\n", r->symbol->label,
			run_addr);
	return create_labelval(change, r->symbol, run_addr, TEMP);
}

static abort_t handle_reloc(struct ksplice_mod_change *change,
			    const struct ksplice_section *sect,
			    const struct ksplice_reloc *r,
			    unsigned long run_addr, enum run_pre_mode mode)
{
	switch (r->howto->type) {
	case KSPLICE_HOWTO_RELOC:
		return handle_howto_reloc(change, sect, r, run_addr, mode);
	case KSPLICE_HOWTO_DATE:
	case KSPLICE_HOWTO_TIME:
		return handle_howto_date(change, sect, r, run_addr, mode);
#ifdef CONFIG_BUG
	case KSPLICE_HOWTO_BUG:
		return handle_bug(change, r, run_addr);
#endif /* CONFIG_BUG */
	case KSPLICE_HOWTO_EXTABLE:
		return handle_extable(change, r, run_addr);
	case KSPLICE_HOWTO_SYMBOL:
		return handle_howto_symbol(change, r, run_addr, mode);
	default:
		ksdebug(change, "Unexpected howto type %d\n", r->howto->type);
		return UNEXPECTED;
	}
}

/*
 * For date/time relocations, we check that the sequence of bytes
 * matches the format of a date or time.
 */
static abort_t handle_howto_date(struct ksplice_mod_change *change,
				 const struct ksplice_section *sect,
				 const struct ksplice_reloc *r,
				 unsigned long run_addr, enum run_pre_mode mode)
{
	abort_t ret;
	char *buf = kmalloc(r->howto->size, GFP_KERNEL);

	if (buf == NULL)
		return OUT_OF_MEMORY;
	if (probe_kernel_read(buf, (void *)run_addr, r->howto->size) == -EFAULT) {
		ret = NO_MATCH;
		goto out;
	}

	switch (r->howto->type) {
	case KSPLICE_HOWTO_TIME:
		if (isdigit(buf[0]) && isdigit(buf[1]) && buf[2] == ':' &&
		    isdigit(buf[3]) && isdigit(buf[4]) && buf[5] == ':' &&
		    isdigit(buf[6]) && isdigit(buf[7]))
			ret = OK;
		else
			ret = NO_MATCH;
		break;
	case KSPLICE_HOWTO_DATE:
		if (isalpha(buf[0]) && isalpha(buf[1]) && isalpha(buf[2]) &&
		    buf[3] == ' ' && (buf[4] == ' ' || isdigit(buf[4])) &&
		    isdigit(buf[5]) && buf[6] == ' ' && isdigit(buf[7]) &&
		    isdigit(buf[8]) && isdigit(buf[9]) && isdigit(buf[10]))
			ret = OK;
		else
			ret = NO_MATCH;
		break;
	default:
		ret = UNEXPECTED;
	}
	if (ret == NO_MATCH && mode == RUN_PRE_INITIAL)
		ksdebug(change, "%s string: \"%.*s\" does not match format\n",
			r->howto->type == KSPLICE_HOWTO_DATE ? "date" : "time",
			r->howto->size, buf);

	if (ret != OK)
		goto out;
	ret = create_labelval(change, r->symbol, run_addr, TEMP);
out:
	kfree(buf);
	return ret;
}

/*
 * Extract the value of a symbol used in a relocation in the pre code
 * during run-pre matching, giving an error if it conflicts with a
 * previously found value of that symbol
 */
static abort_t handle_howto_reloc(struct ksplice_mod_change *change,
				  const struct ksplice_section *sect,
				  const struct ksplice_reloc *r,
				  unsigned long run_addr,
				  enum run_pre_mode mode)
{
	struct ksplice_section *sym_sect = symbol_section(change, r->symbol);
	unsigned long offset = r->target_addend;
	unsigned long val;
	abort_t ret;

	ret = read_reloc_value(change, r, run_addr, &val);
	if (ret != OK)
		return ret;
	if (r->howto->pcrel)
		val += run_addr;

#ifndef CONFIG_FUNCTION_DATA_SECTIONS
	if (sym_sect == NULL || sym_sect->match_map == NULL || offset == 0) {
		;
	} else if (offset < 0 || offset >= sym_sect->size) {
		ksdebug(change, "Out of range relocation: %s+%lx -> %s+%lx",
			sect->symbol->label, r->blank_addr - sect->address,
			r->symbol->label, offset);
		return NO_MATCH;
	} else if (sect == sym_sect && sect->match_map[offset] == NULL) {
		sym_sect->match_map[offset] =
		    (const unsigned char *)r->symbol->value + offset;
		sym_sect->unmatched++;
	} else if (sect == sym_sect && (unsigned long)sect->match_map[offset] ==
		   r->symbol->value + offset) {
		;
	} else if (sect == sym_sect) {
		ksdebug(change, "Relocations to nonmatching locations within "
			"section %s: %lx does not match %lx\n",
			sect->symbol->label, offset,
			(unsigned long)sect->match_map[offset] -
			r->symbol->value);
		return NO_MATCH;
	} else if ((sym_sect->flags & KSPLICE_SECTION_MATCHED) == 0) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(change, "Delaying matching of %s due to reloc "
				"from to unmatching section: %s+%lx\n",
				sect->symbol->label, r->symbol->label, offset);
		return NO_MATCH;
	} else if (sym_sect->match_map[offset] == NULL) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(change, "Relocation not to instruction "
				"boundary: %s+%lx -> %s+%lx",
				sect->symbol->label, r->blank_addr -
				sect->address, r->symbol->label, offset);
		return NO_MATCH;
	} else if ((unsigned long)sym_sect->match_map[offset] !=
		   r->symbol->value + offset) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(change, "Match map shift %s+%lx: %lx != %lx\n",
				r->symbol->label, offset,
				r->symbol->value + offset,
				(unsigned long)sym_sect->match_map[offset]);
		val += r->symbol->value + offset -
		    (unsigned long)sym_sect->match_map[offset];
	}
#endif /* !CONFIG_FUNCTION_DATA_SECTIONS */

	if (mode == RUN_PRE_INITIAL)
		ksdebug(change, "run-pre: reloc at r_a=%lx p_a=%lx to %s+%lx: "
			"found %s = %lx\n", run_addr, r->blank_addr,
			r->symbol->label, offset, r->symbol->label, val);

	if (contains_canary(change, run_addr, r->howto) != 0) {
		ksdebug(change, "Aborted.  Unexpected canary in run code at %lx"
			"\n", run_addr);
		return UNEXPECTED;
	}

	if ((sect->flags & KSPLICE_SECTION_DATA) != 0 &&
	    sect->symbol == r->symbol)
		return OK;
	ret = create_labelval(change, r->symbol, val, TEMP);
	if (ret == NO_MATCH && mode == RUN_PRE_INITIAL)
		ksdebug(change, "run-pre: reloc at r_a=%lx p_a=%lx: labelval "
			"%s = %lx does not match expected %lx\n", run_addr,
			r->blank_addr, r->symbol->label, r->symbol->value, val);

	if (ret != OK)
		return ret;
	if (sym_sect != NULL && (sym_sect->flags & KSPLICE_SECTION_MATCHED) == 0
	    && (sym_sect->flags & KSPLICE_SECTION_STRING) != 0) {
		if (mode == RUN_PRE_INITIAL)
			ksdebug(change, "Recursively comparing string section "
				"%s\n", sym_sect->symbol->label);
		else if (mode == RUN_PRE_DEBUG)
			ksdebug(change, "[str start] ");
		ret = run_pre_cmp(change, sym_sect, val, NULL, mode);
		if (mode == RUN_PRE_DEBUG)
			ksdebug(change, "[str end] ");
		if (ret == OK && mode == RUN_PRE_INITIAL)
			ksdebug(change, "Successfully matched string section %s"
				"\n", sym_sect->symbol->label);
		else if (mode == RUN_PRE_INITIAL)
			ksdebug(change, "Failed to match string section %s\n",
				sym_sect->symbol->label);
	}
	return ret;
}

#ifdef CONFIG_GENERIC_BUG
#ifdef KSPLICE_NO_KERNEL_SUPPORT
EXTRACT_SYMBOL(find_bug);
#endif /* KSPLICE_NO_KERNEL_SUPPORT */
static abort_t handle_bug(struct ksplice_mod_change *change,
			  const struct ksplice_reloc *r, unsigned long run_addr)
{
	const struct bug_entry *run_bug = find_bug(run_addr);
	struct ksplice_section *bug_sect = symbol_section(change, r->symbol);
	if (run_bug == NULL)
		return NO_MATCH;
	if (bug_sect == NULL)
		return UNEXPECTED;
	return create_labelval(change, bug_sect->symbol, (unsigned long)run_bug,
			       TEMP);
}
#endif /* CONFIG_GENERIC_BUG */

#ifdef KSPLICE_NO_KERNEL_SUPPORT
EXTRACT_SYMBOL(search_exception_tables);
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

static abort_t handle_extable(struct ksplice_mod_change *change,
			      const struct ksplice_reloc *r,
			      unsigned long run_addr)
{
	const struct exception_table_entry *run_ent =
	    search_exception_tables(run_addr);
	struct ksplice_section *ex_sect = symbol_section(change, r->symbol);
	if (run_ent == NULL)
		return NO_MATCH;
	if (ex_sect == NULL)
		return UNEXPECTED;
	return create_labelval(change, ex_sect->symbol, (unsigned long)run_ent,
			       TEMP);
}

static int symbol_section_bsearch_compare(const void *a, const void *b)
{
	const struct ksplice_symbol *sym = a;
	const struct ksplice_section *sect = b;
	return strcmp(sym->label, sect->symbol->label);
}

static int compare_section_labels(const void *va, const void *vb)
{
	const struct ksplice_section *a = va, *b = vb;
	return strcmp(a->symbol->label, b->symbol->label);
}

static struct ksplice_section *symbol_section(struct ksplice_mod_change *change,
					      const struct ksplice_symbol *sym)
{
	return bsearch(sym, change->old_code.sections,
		       change->old_code.sections_end -
		       change->old_code.sections,
		       sizeof(struct ksplice_section),
		       symbol_section_bsearch_compare);
}

/* Find the relocation for the oldaddr of a ksplice_patch */
static const struct ksplice_reloc *
patch_reloc(struct ksplice_mod_change *change,
	    const struct ksplice_patch *p)
{
	unsigned long addr = (unsigned long)&p->oldaddr;
	const struct ksplice_reloc *r =
	    find_reloc(change->new_code.relocs, change->new_code.relocs_end,
		       addr, sizeof(addr));
	if (r == NULL || r->blank_addr < addr ||
	    r->blank_addr >= addr + sizeof(addr))
		return NULL;
	return r;
}

/*
 * Populates vals with the possible values for ksym from the various
 * sources Ksplice uses to resolve symbols
 */
static abort_t lookup_symbol(struct ksplice_mod_change *change,
			     const struct ksplice_symbol *ksym,
			     struct list_head *vals)
{
	abort_t ret;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return OK;
#endif /* KSPLICE_STANDALONE */

	if (ksym->candidate_vals == NULL) {
		release_vals(vals);
		ksdebug(change, "using detected sym %s=%lx\n", ksym->label,
			ksym->value);
		return add_candidate_val(change, vals, ksym->value);
	}

#ifdef CONFIG_MODULE_UNLOAD
	if (strcmp(ksym->label, "cleanup_module") == 0 && change->target != NULL
	    && change->target->exit != NULL) {
		ret = add_candidate_val(change, vals,
					(unsigned long)change->target->exit);
		if (ret != OK)
			return ret;
	}
#endif

	if (ksym->name != NULL) {
		struct candidate_val *val;
		list_for_each_entry(val, ksym->candidate_vals, list) {
			ret = add_candidate_val(change, vals, val->val);
			if (ret != OK)
				return ret;
		}

		ret = new_export_lookup(change, ksym->name, vals);
		if (ret != OK)
			return ret;
	}

	return OK;
}

#ifdef KSPLICE_STANDALONE
static abort_t
add_system_map_candidates(struct ksplice_mod_change *change,
			  const struct ksplice_system_map *start,
			  const struct ksplice_system_map *end,
			  const char *label, struct list_head *vals)
{
	abort_t ret;
	long off;
	int i;
	const struct ksplice_system_map *smap;

	/* Some Fedora kernel releases have System.map files whose symbol
	 * addresses disagree with the running kernel by a constant address
	 * offset because of the CONFIG_PHYSICAL_START and CONFIG_PHYSICAL_ALIGN
	 * values used to compile these kernels.  This constant address offset
	 * is always a multiple of 0x100000.
	 *
	 * If we observe an offset that is NOT a multiple of 0x100000, then the
	 * user provided us with an incorrect System.map file, and we should
	 * abort.
	 * If we observe an offset that is a multiple of 0x100000, then we can
	 * adjust the System.map address values accordingly and proceed.
	 */
	off = (unsigned long)printk - change->map_printk;
	if (off & 0xfffff) {
		ksdebug(change,
			"Aborted.  System.map does not match kernel.\n");
		return BAD_SYSTEM_MAP;
	}

	smap = bsearch(label, start, end - start, sizeof(*smap),
		       system_map_bsearch_compare);
	if (smap == NULL)
		return OK;

	for (i = 0; i < smap->nr_candidates; i++) {
		ret = add_candidate_val(change, vals,
					smap->candidates[i] + off);
		if (ret != OK)
			return ret;
	}
	return OK;
}

static int system_map_bsearch_compare(const void *key, const void *elt)
{
	const struct ksplice_system_map *map = elt;
	const char *label = key;
	return strcmp(label, map->label);
}
#endif /* !KSPLICE_STANDALONE */

/*
 * An update could one module to export a symbol and at the same time
 * change another module to use that symbol.  This violates the normal
 * situation where the changes can be handled independently.
 *
 * new_export_lookup obtains symbol values from the changes to the
 * exported symbol table made by other changes.
 */
static abort_t new_export_lookup(struct ksplice_mod_change *ichange,
				 const char *name, struct list_head *vals)
{
	struct ksplice_mod_change *change;
	struct ksplice_patch *p;
	list_for_each_entry(change, &ichange->update->changes, list) {
		for (p = change->patches; p < change->patches_end; p++) {
			const struct kernel_symbol *sym;
			const struct ksplice_reloc *r;
			if (p->type != KSPLICE_PATCH_EXPORT ||
			    strcmp(name, *(const char **)p->contents) != 0)
				continue;

			/* Check that the p->oldaddr reloc has been resolved. */
			r = patch_reloc(change, p);
			if (r == NULL ||
			    contains_canary(change, r->blank_addr,
					    r->howto) != 0)
				continue;
			sym = (const struct kernel_symbol *)r->symbol->value;

			/*
			 * Check that the sym->value reloc has been resolved,
			 * if there is a Ksplice relocation there.
			 */
			r = find_reloc(change->new_code.relocs,
				       change->new_code.relocs_end,
				       (unsigned long)&sym->value,
				       sizeof(&sym->value));
			if (r != NULL &&
			    r->blank_addr == (unsigned long)&sym->value &&
			    contains_canary(change, r->blank_addr,
					    r->howto) != 0)
				continue;
			return add_candidate_val(ichange, vals, sym->value);
		}
	}
	return OK;
}

#ifdef KSPLICE_STANDALONE
EXTRACT_SYMBOL(bust_spinlocks);
#endif /* KSPLICE_STANDALONE */

/*
 * When patch_action is called, the update should be fully prepared.
 * patch_action will try to actually insert or remove trampolines for
 * the update.
 */
static abort_t patch_action(struct update *update, enum ksplice_action action)
{
	static int (*const __patch_actions[KS_ACTIONS])(void *) = {
		[KS_APPLY] = __apply_patches,
		[KS_REVERSE] = __reverse_patches,
	};
	int i;
	abort_t ret;
	struct ksplice_mod_change *change;

	ret = map_trampoline_pages(update);
	if (ret != OK)
		return ret;

	list_for_each_entry(change, &update->changes, list) {
		const typeof(int (*)(void)) *f;
		for (f = change->hooks[action].pre;
		     f < change->hooks[action].pre_end; f++) {
			if ((*f)() != 0) {
				ret = CALL_FAILED;
				goto out;
			}
		}
	}

	for (i = 0; i < 5; i++) {
		cleanup_conflicts(update);
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(1);
#endif /* KSPLICE_STANDALONE */
		ret = (__force abort_t)stop_machine(__patch_actions[action],
						    update, NULL);
#ifdef KSPLICE_STANDALONE
		bust_spinlocks(0);
#endif /* KSPLICE_STANDALONE */
		if (ret != CODE_BUSY)
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
	}
out:
	unmap_trampoline_pages(update);

	if (ret == CODE_BUSY) {
		print_conflicts(update);
		_ksdebug(update, "Aborted %s.  stack check: to-be-%s "
			 "code is busy.\n", update->kid,
			 action == KS_APPLY ? "replaced" : "reversed");
	} else if (ret == ALREADY_REVERSED) {
		_ksdebug(update, "Aborted %s.  Ksplice update %s is already "
			 "reversed.\n", update->kid, update->kid);
	} else if (ret == MODULE_BUSY) {
		_ksdebug(update, "Update %s is in use by another module\n",
			 update->kid);
	}

	if (ret != OK) {
		list_for_each_entry(change, &update->changes, list) {
			const typeof(void (*)(void)) *f;
			for (f = change->hooks[action].fail;
			     f < change->hooks[action].fail_end; f++)
				(*f)();
		}

		return ret;
	}

	list_for_each_entry(change, &update->changes, list) {
		const typeof(void (*)(void)) *f;
		for (f = change->hooks[action].post;
		     f < change->hooks[action].post_end; f++)
			(*f)();
	}

	_ksdebug(update, "Atomic patch %s for %s complete\n",
		 action == KS_APPLY ? "insertion" : "removal", update->kid);
	return OK;
}

/* Atomically insert the update; run from within stop_machine */
static int __apply_patches(void *updateptr)
{
	struct update *update = updateptr;
	struct ksplice_mod_change *change;
	struct ksplice_module_list_entry *entry;
	struct ksplice_patch *p;
	abort_t ret;

	if (update->stage == STAGE_APPLIED)
		return (__force int)OK;

	if (update->stage != STAGE_PREPARING)
		return (__force int)UNEXPECTED;

	ret = check_each_task(update);
	if (ret != OK)
		return (__force int)ret;

	list_for_each_entry(change, &update->changes, list) {
		if (try_module_get(change->new_code_mod) != 1) {
			struct ksplice_mod_change *change1;
			list_for_each_entry(change1, &update->changes, list) {
				if (change1 == change)
					break;
				module_put(change1->new_code_mod);
			}
			module_put(THIS_MODULE);
			return (__force int)UNEXPECTED;
		}
	}

	list_for_each_entry(change, &update->changes, list) {
		const typeof(int (*)(void)) *f;
		for (f = change->hooks[KS_APPLY].check;
		     f < change->hooks[KS_APPLY].check_end; f++) {
			if ((*f)() != 0)
				return (__force int)CALL_FAILED;
		}
	}

	/* Commit point: the update application will succeed. */

	update->stage = STAGE_APPLIED;
#ifdef TAINT_KSPLICE
	add_taint(TAINT_KSPLICE);
#endif

	list_for_each_entry(entry, &update->ksplice_module_list, update_list)
		list_add(&entry->list, &ksplice_modules);

	list_for_each_entry(change, &update->changes, list) {
		for (p = change->patches; p < change->patches_end; p++)
			insert_trampoline(p);
	}

	list_for_each_entry(change, &update->changes, list) {
		const typeof(void (*)(void)) *f;
		for (f = change->hooks[KS_APPLY].intra;
		     f < change->hooks[KS_APPLY].intra_end; f++)
			(*f)();
	}

	return (__force int)OK;
}

/* Atomically remove the update; run from within stop_machine */
static int __reverse_patches(void *updateptr)
{
	struct update *update = updateptr;
	struct ksplice_mod_change *change;
	struct ksplice_module_list_entry *entry;
	const struct ksplice_patch *p;
	abort_t ret;

	if (update->stage != STAGE_APPLIED)
		return (__force int)OK;

#ifdef CONFIG_MODULE_UNLOAD
	list_for_each_entry(change, &update->changes, list) {
		if (module_refcount(change->new_code_mod) != 1)
			return (__force int)MODULE_BUSY;
	}
#endif /* CONFIG_MODULE_UNLOAD */

	list_for_each_entry(entry, &update->ksplice_module_list, update_list) {
		if (!entry->applied &&
		    find_module(entry->target_mod_name) != NULL)
			return COLD_UPDATE_LOADED;
	}

	ret = check_each_task(update);
	if (ret != OK)
		return (__force int)ret;

	list_for_each_entry(change, &update->changes, list) {
		for (p = change->patches; p < change->patches_end; p++) {
			ret = verify_trampoline(change, p);
			if (ret != OK)
				return (__force int)ret;
		}
	}

	list_for_each_entry(change, &update->changes, list) {
		const typeof(int (*)(void)) *f;
		for (f = change->hooks[KS_REVERSE].check;
		     f < change->hooks[KS_REVERSE].check_end; f++) {
			if ((*f)() != 0)
				return (__force int)CALL_FAILED;
		}
	}

	/* Commit point: the update reversal will succeed. */

	update->stage = STAGE_REVERSED;

	list_for_each_entry(change, &update->changes, list)
		module_put(change->new_code_mod);

	list_for_each_entry(entry, &update->ksplice_module_list, update_list)
		list_del(&entry->list);

	list_for_each_entry(change, &update->changes, list) {
		const typeof(void (*)(void)) *f;
		for (f = change->hooks[KS_REVERSE].intra;
		     f < change->hooks[KS_REVERSE].intra_end; f++)
			(*f)();
	}

	list_for_each_entry(change, &update->changes, list) {
		for (p = change->patches; p < change->patches_end; p++)
			remove_trampoline(p);
	}

	return (__force int)OK;
}

/*
 * Check whether any thread's instruction pointer or any address of
 * its stack is contained in one of the safety_records associated with
 * the update.
 *
 * check_each_task must be called from inside stop_machine, because it
 * does not take tasklist_lock (which cannot be held by anyone else
 * during stop_machine).
 */
static abort_t check_each_task(struct update *update)
{
	const struct task_struct *g, *p;
	abort_t status = OK, ret;
	do_each_thread(g, p) {
		/* do_each_thread is a double loop! */
		ret = check_task(update, p, false);
		if (ret != OK) {
			check_task(update, p, true);
			status = ret;
		}
		if (ret != OK && ret != CODE_BUSY)
			return ret;
	} while_each_thread(g, p);
	return status;
}

#ifdef KSPLICE_NO_KERNEL_SUPPORT
EXTRACT_SYMBOL(task_curr);
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

static abort_t check_task(struct update *update,
			  const struct task_struct *t, bool rerun)
{
	abort_t status, ret;
	struct conflict *conf = NULL;

	if (rerun) {
		conf = kmalloc(sizeof(*conf), GFP_ATOMIC);
		if (conf == NULL)
			return OUT_OF_MEMORY;
		conf->process_name = kstrdup(t->comm, GFP_ATOMIC);
		if (conf->process_name == NULL) {
			kfree(conf);
			return OUT_OF_MEMORY;
		}
		conf->pid = t->pid;
		INIT_LIST_HEAD(&conf->stack);
		list_add(&conf->list, &update->conflicts);
	}

	if (t->state == TASK_DEAD)
		return OK;

	if (KSPLICE_CHECK_IP)
		status = check_address(update, conf, KSPLICE_IP(t));
	else
		status = OK;

	ret = check_address(update, conf,
			    (unsigned long)task_thread_info(t)->
			    restart_block.fn);
	if (status == OK)
		status = ret;

	if (t == current) {
		ret = check_stack(update, conf, task_thread_info(t),
				  (unsigned long *)__builtin_frame_address(0));
		if (status == OK)
			status = ret;
	} else if (!task_curr(t)) {
		ret = check_stack(update, conf, task_thread_info(t),
				  (unsigned long *)KSPLICE_SP(t));
		if (status == OK)
			status = ret;
	} else if (!is_stop_machine(t)) {
		status = UNEXPECTED_RUNNING_TASK;
	}
	return status;
}

static abort_t check_stack(struct update *update, struct conflict *conf,
			   const struct thread_info *tinfo,
			   const unsigned long *stack)
{
	abort_t status = OK, ret;
	unsigned long addr;

	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		ret = check_address(update, conf, addr);
		if (ret != OK)
			status = ret;
	}
	return status;
}

static abort_t check_address(struct update *update,
			     struct conflict *conf, unsigned long addr)
{
	abort_t status = OK, ret;
	const struct safety_record *rec;
	struct ksplice_mod_change *change;
	struct conflict_addr *ca = NULL;

	if (conf != NULL) {
		ca = kmalloc(sizeof(*ca), GFP_ATOMIC);
		if (ca == NULL)
			return OUT_OF_MEMORY;
		ca->addr = addr;
		ca->has_conflict = false;
		ca->label = NULL;
		list_add(&ca->list, &conf->stack);
	}

	list_for_each_entry(change, &update->changes, list) {
		unsigned long tramp_addr = follow_trampolines(change, addr);
		list_for_each_entry(rec, &change->safety_records, list) {
			ret = check_record(ca, rec, tramp_addr);
			if (ret != OK)
				status = ret;
		}
	}
	return status;
}

static abort_t check_record(struct conflict_addr *ca,
			    const struct safety_record *rec, unsigned long addr)
{
	if (addr >= rec->addr && addr < rec->addr + rec->size) {
		if (ca != NULL) {
			ca->label = rec->label;
			ca->has_conflict = true;
		}
		return CODE_BUSY;
	}
	return OK;
}

/* Is the task one of the stop_machine tasks? */
static bool is_stop_machine(const struct task_struct *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	const char *kstop_prefix = "migration/";
#else
	const char *kstop_prefix = "kstop/";
#endif /* LINUX_VERSION_CODE */
	const char *num;
	if (!strstarts(t->comm, kstop_prefix))
		return false;
	num = t->comm + strlen(kstop_prefix);
	return num[strspn(num, "0123456789")] == '\0';
}

static void cleanup_conflicts(struct update *update)
{
	struct conflict *conf;
	list_for_each_entry(conf, &update->conflicts, list) {
		clear_list(&conf->stack, struct conflict_addr, list);
		kfree(conf->process_name);
	}
	clear_list(&update->conflicts, struct conflict, list);
}

static void print_conflicts(struct update *update)
{
	const struct conflict *conf;
	const struct conflict_addr *ca;
	list_for_each_entry(conf, &update->conflicts, list) {
		_ksdebug(update, "stack check: pid %d (%s):", conf->pid,
			 conf->process_name);
		list_for_each_entry(ca, &conf->stack, list) {
			_ksdebug(update, " %lx", ca->addr);
			if (ca->has_conflict)
				_ksdebug(update, " [<-CONFLICT]");
		}
		_ksdebug(update, "\n");
	}
}

static void insert_trampoline(struct ksplice_patch *p)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy(p->saved, p->vaddr, p->size);
	memcpy(p->vaddr, p->contents, p->size);
	flush_icache_range(p->oldaddr, p->oldaddr + p->size);
	set_fs(old_fs);
}

static abort_t verify_trampoline(struct ksplice_mod_change *change,
				 const struct ksplice_patch *p)
{
	if (memcmp(p->vaddr, p->contents, p->size) != 0) {
		ksdebug(change, "Aborted.  Trampoline at %lx has been "
			"overwritten.\n", p->oldaddr);
		return CODE_BUSY;
	}
	return OK;
}

static void remove_trampoline(const struct ksplice_patch *p)
{
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	memcpy(p->vaddr, p->saved, p->size);
	flush_icache_range(p->oldaddr, p->oldaddr + p->size);
	set_fs(old_fs);
}

/* Returns NO_MATCH if there's already a labelval with a different value */
static abort_t create_labelval(struct ksplice_mod_change *change,
			       struct ksplice_symbol *ksym,
			       unsigned long val, int status)
{
	val = follow_trampolines(change, val);
	if (ksym->candidate_vals == NULL)
		return ksym->value == val ? OK : NO_MATCH;

	ksym->value = val;
	if (status == TEMP) {
		struct labelval *lv = kmalloc(sizeof(*lv), GFP_KERNEL);
		if (lv == NULL)
			return OUT_OF_MEMORY;
		lv->symbol = ksym;
		lv->saved_vals = ksym->candidate_vals;
		list_add(&lv->list, &change->temp_labelvals);
	}
	ksym->candidate_vals = NULL;
	return OK;
}

/*
 * Creates a new safety_record for a old_code section based on its
 * ksplice_section and run-pre matching information.
 */
static abort_t create_safety_record(struct ksplice_mod_change *change,
				    const struct ksplice_section *sect,
				    struct list_head *record_list,
				    unsigned long run_addr,
				    unsigned long run_size)
{
	struct safety_record *rec;
	struct ksplice_patch *p;

	if (record_list == NULL)
		return OK;

	for (p = change->patches; p < change->patches_end; p++) {
		const struct ksplice_reloc *r = patch_reloc(change, p);
		if (strcmp(sect->symbol->label, r->symbol->label) == 0)
			break;
	}
	if (p >= change->patches_end)
		return OK;

	rec = kmalloc(sizeof(*rec), GFP_KERNEL);
	if (rec == NULL)
		return OUT_OF_MEMORY;
	/*
	 * The old_code might be unloaded when checking reversing
	 * patches, so we need to kstrdup the label here.
	 */
	rec->label = kstrdup(sect->symbol->label, GFP_KERNEL);
	if (rec->label == NULL) {
		kfree(rec);
		return OUT_OF_MEMORY;
	}
	rec->addr = run_addr;
	rec->size = run_size;

	list_add(&rec->list, record_list);
	return OK;
}

static abort_t add_candidate_val(struct ksplice_mod_change *change,
				 struct list_head *vals, unsigned long val)
{
	struct candidate_val *tmp, *new;

/*
 * Careful: follow trampolines before comparing values so that we do
 * not mistake the obsolete function for another copy of the function.
 */
	val = follow_trampolines(change, val);

	list_for_each_entry(tmp, vals, list) {
		if (tmp->val == val)
			return OK;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (new == NULL)
		return OUT_OF_MEMORY;
	new->val = val;
	list_add(&new->list, vals);
	return OK;
}

static void release_vals(struct list_head *vals)
{
	clear_list(vals, struct candidate_val, list);
}

/*
 * The temp_labelvals list is used to cache those temporary labelvals
 * that have been created to cross-check the symbol values obtained
 * from different relocations within a single section being matched.
 *
 * If status is VAL, commit the temp_labelvals as final values.
 *
 * If status is NOVAL, restore the list of possible values to the
 * ksplice_symbol, so that it no longer has a known value.
 */
static void set_temp_labelvals(struct ksplice_mod_change *change, int status)
{
	struct labelval *lv, *n;
	list_for_each_entry_safe(lv, n, &change->temp_labelvals, list) {
		if (status == NOVAL) {
			lv->symbol->candidate_vals = lv->saved_vals;
		} else {
			release_vals(lv->saved_vals);
			kfree(lv->saved_vals);
		}
		list_del(&lv->list);
		kfree(lv);
	}
}

/* Is there a Ksplice canary with given howto at blank_addr? */
static int contains_canary(struct ksplice_mod_change *change,
			   unsigned long blank_addr,
			   const struct ksplice_reloc_howto *howto)
{
	switch (howto->size) {
	case 1:
		return (*(uint8_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
	case 2:
		return (*(uint16_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
	case 4:
		return (*(uint32_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
#if BITS_PER_LONG >= 64
	case 8:
		return (*(uint64_t *)blank_addr & howto->dst_mask) ==
		    (KSPLICE_CANARY & howto->dst_mask);
#endif /* BITS_PER_LONG */
	default:
		ksdebug(change, "Aborted.  Invalid relocation size.\n");
		return -1;
	}
}

#ifdef KSPLICE_NO_KERNEL_SUPPORT
EXTRACT_SYMBOL(__kernel_text_address);
#endif /* KSPLICE_NO_KERNEL_SUPPORT */

/*
 * Compute the address of the code you would actually run if you were
 * to call the function at addr (i.e., follow the sequence of jumps
 * starting at addr)
 */
static unsigned long follow_trampolines(struct ksplice_mod_change *change,
					unsigned long addr)
{
	unsigned long new_addr;
	struct module *m;

	while (1) {
#ifdef KSPLICE_STANDALONE
		if (!bootstrapped)
			return addr;
#endif /* KSPLICE_STANDALONE */
		if (!__kernel_text_address(addr) ||
		    trampoline_target(change, addr, &new_addr) != OK)
			return addr;
		m = __module_text_address(new_addr);
		if (m == NULL || m == change->target ||
		    !strstarts(m->name, "ksplice"))
			return addr;
		addr = new_addr;
	}
}

/* Does module a patch module b? */
static bool patches_module(const struct module *a, const struct module *b)
{
#ifdef KSPLICE_NO_KERNEL_SUPPORT
	const char *name;
	const char *modname = b == NULL ? "vmlinux" : b->name;
	if (a == b)
		return true;
	if (a == NULL || !strstarts(a->name, "ksplice_"))
		return false;
	name = a->name + strlen("ksplice_");
	name += strcspn(name, "_");
	if (name[0] != '_')
		return false;
	name++;
	return strstarts(name, modname) &&
	    strcmp(name + strlen(modname), "_new") == 0;
#else /* !KSPLICE_NO_KERNEL_SUPPORT */
	struct ksplice_module_list_entry *entry;
	if (a == b)
		return true;
	list_for_each_entry(entry, &ksplice_modules, list) {
		if (strcmp(entry->target_mod_name, b->name) == 0 &&
		    strcmp(entry->new_code_mod_name, a->name) == 0)
			return true;
	}
	return false;
#endif /* KSPLICE_NO_KERNEL_SUPPORT */
}

static bool singular(struct list_head *list)
{
	return !list_empty(list) && list->next->next == list;
}

static void *bsearch(const void *key, const void *base, size_t n,
		     size_t size, int (*cmp)(const void *key, const void *elt))
{
	int start = 0, end = n - 1, mid, result;
	if (n == 0)
		return NULL;
	while (start <= end) {
		mid = (start + end) / 2;
		result = cmp(key, base + mid * size);
		if (result < 0)
			end = mid - 1;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)base + mid * size;
	}
	return NULL;
}

static int compare_relocs(const void *a, const void *b)
{
	const struct ksplice_reloc *ra = a, *rb = b;
	if (ra->blank_addr > rb->blank_addr)
		return 1;
	else if (ra->blank_addr < rb->blank_addr)
		return -1;
	else
		return ra->howto->size - rb->howto->size;
}

#ifdef KSPLICE_STANDALONE
static int compare_system_map(const void *a, const void *b)
{
	const struct ksplice_system_map *sa = a, *sb = b;
	return strcmp(sa->label, sb->label);
}
#endif /* KSPLICE_STANDALONE */

#ifdef CONFIG_DEBUG_FS
static abort_t init_debug_buf(struct update *update)
{
	update->debug_blob.size = 0;
	update->debug_blob.data = NULL;
	update->debugfs_dentry =
	    debugfs_create_blob(update->name, S_IFREG | S_IRUSR, NULL,
				&update->debug_blob);
	if (update->debugfs_dentry == NULL)
		return OUT_OF_MEMORY;
	return OK;
}

static void clear_debug_buf(struct update *update)
{
	if (update->debugfs_dentry == NULL)
		return;
	debugfs_remove(update->debugfs_dentry);
	update->debugfs_dentry = NULL;
	update->debug_blob.size = 0;
	vfree(update->debug_blob.data);
	update->debug_blob.data = NULL;
}

static int _ksdebug(struct update *update, const char *fmt, ...)
{
	va_list args;
	unsigned long size, old_size, new_size;

	if (update->debug == 0)
		return 0;

	/* size includes the trailing '\0' */
	va_start(args, fmt);
	size = 1 + vsnprintf(update->debug_blob.data, 0, fmt, args);
	va_end(args);
	old_size = update->debug_blob.size == 0 ? 0 :
	    max(PAGE_SIZE, roundup_pow_of_two(update->debug_blob.size));
	new_size = update->debug_blob.size + size == 0 ? 0 :
	    max(PAGE_SIZE, roundup_pow_of_two(update->debug_blob.size + size));
	if (new_size > old_size) {
		char *buf = vmalloc(new_size);
		if (buf == NULL)
			return -ENOMEM;
		memcpy(buf, update->debug_blob.data, update->debug_blob.size);
		vfree(update->debug_blob.data);
		update->debug_blob.data = buf;
	}
	va_start(args, fmt);
	update->debug_blob.size += vsnprintf(update->debug_blob.data +
					     update->debug_blob.size,
					     size, fmt, args);
	va_end(args);
	return 0;
}
#else /* CONFIG_DEBUG_FS */
static abort_t init_debug_buf(struct update *update)
{
	return OK;
}

static void clear_debug_buf(struct update *update)
{
	return;
}

static int _ksdebug(struct update *update, const char *fmt, ...)
{
	va_list args;

	if (update->debug == 0)
		return 0;

	if (!update->debug_continue_line)
		printk(KERN_DEBUG "ksplice: ");

	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	update->debug_continue_line =
	    fmt[0] == '\0' || fmt[strlen(fmt) - 1] != '\n';
	return 0;
}
#endif /* CONFIG_DEBUG_FS */

struct update_attribute {
	struct attribute attr;
	ssize_t (*show)(struct update *update, char *buf);
	ssize_t (*store)(struct update *update, const char *buf, size_t len);
};

static ssize_t update_attr_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct update_attribute *attribute =
	    container_of(attr, struct update_attribute, attr);
	struct update *update = container_of(kobj, struct update, kobj);
	if (attribute->show == NULL)
		return -EIO;
	return attribute->show(update, buf);
}

static ssize_t update_attr_store(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t len)
{
	struct update_attribute *attribute =
	    container_of(attr, struct update_attribute, attr);
	struct update *update = container_of(kobj, struct update, kobj);
	if (attribute->store == NULL)
		return -EIO;
	return attribute->store(update, buf, len);
}

static struct sysfs_ops update_sysfs_ops = {
	.show = update_attr_show,
	.store = update_attr_store,
};

static void update_release(struct kobject *kobj)
{
	struct update *update;
	update = container_of(kobj, struct update, kobj);
	cleanup_ksplice_update(update);
}

static ssize_t stage_show(struct update *update, char *buf)
{
	switch (update->stage) {
	case STAGE_PREPARING:
		return snprintf(buf, PAGE_SIZE, "preparing\n");
	case STAGE_APPLIED:
		return snprintf(buf, PAGE_SIZE, "applied\n");
	case STAGE_REVERSED:
		return snprintf(buf, PAGE_SIZE, "reversed\n");
	}
	return 0;
}

static ssize_t abort_cause_show(struct update *update, char *buf)
{
	switch (update->abort_cause) {
	case OK:
		return snprintf(buf, PAGE_SIZE, "ok\n");
	case NO_MATCH:
		return snprintf(buf, PAGE_SIZE, "no_match\n");
#ifdef KSPLICE_STANDALONE
	case BAD_SYSTEM_MAP:
		return snprintf(buf, PAGE_SIZE, "bad_system_map\n");
#endif /* KSPLICE_STANDALONE */
	case CODE_BUSY:
		return snprintf(buf, PAGE_SIZE, "code_busy\n");
	case MODULE_BUSY:
		return snprintf(buf, PAGE_SIZE, "module_busy\n");
	case OUT_OF_MEMORY:
		return snprintf(buf, PAGE_SIZE, "out_of_memory\n");
	case FAILED_TO_FIND:
		return snprintf(buf, PAGE_SIZE, "failed_to_find\n");
	case ALREADY_REVERSED:
		return snprintf(buf, PAGE_SIZE, "already_reversed\n");
	case MISSING_EXPORT:
		return snprintf(buf, PAGE_SIZE, "missing_export\n");
	case UNEXPECTED_RUNNING_TASK:
		return snprintf(buf, PAGE_SIZE, "unexpected_running_task\n");
	case TARGET_NOT_LOADED:
		return snprintf(buf, PAGE_SIZE, "target_not_loaded\n");
	case CALL_FAILED:
		return snprintf(buf, PAGE_SIZE, "call_failed\n");
	case COLD_UPDATE_LOADED:
		return snprintf(buf, PAGE_SIZE, "cold_update_loaded\n");
	case UNEXPECTED:
		return snprintf(buf, PAGE_SIZE, "unexpected\n");
	default:
		return snprintf(buf, PAGE_SIZE, "unknown\n");
	}
	return 0;
}

static ssize_t conflict_show(struct update *update, char *buf)
{
	const struct conflict *conf;
	const struct conflict_addr *ca;
	int lastused = 0;
	mutex_lock(&module_mutex);
	list_for_each_entry(conf, &update->conflicts, list) {
		int used = lastused;
		used += snprintf(buf + used, PAGE_SIZE - used, "%s %d",
				 conf->process_name, conf->pid);
		if (used >= PAGE_SIZE)
			goto out;
		list_for_each_entry(ca, &conf->stack, list) {
			if (!ca->has_conflict)
				continue;
			used += snprintf(buf + used, PAGE_SIZE - used, " %s",
					 ca->label);
			if (used >= PAGE_SIZE)
				goto out;
		}
		used += snprintf(buf + used, PAGE_SIZE - used, "\n");
		if (used >= PAGE_SIZE)
			goto out;
		lastused = used;
	}
out:
	mutex_unlock(&module_mutex);
	return lastused;
}

/* Used to pass maybe_cleanup_ksplice_update to kthread_run */
static int maybe_cleanup_ksplice_update_wrapper(void *updateptr)
{
	struct update *update = updateptr;
	mutex_lock(&module_mutex);
	maybe_cleanup_ksplice_update(update);
	mutex_unlock(&module_mutex);
	return 0;
}

EXTRACT_SYMBOL(set_all_modules_text_ro);
EXTRACT_SYMBOL(set_all_modules_text_rw);

static ssize_t stage_store(struct update *update, const char *buf, size_t len)
{
	enum stage old_stage;
	set_all_modules_text_rw();
	mutex_lock(&module_mutex);
	old_stage = update->stage;
	if ((strncmp(buf, "applied", len) == 0 ||
	     strncmp(buf, "applied\n", len) == 0) &&
	    update->stage == STAGE_PREPARING)
		update->abort_cause = apply_update(update);
	else if ((strncmp(buf, "reversed", len) == 0 ||
		  strncmp(buf, "reversed\n", len) == 0) &&
		 update->stage == STAGE_APPLIED)
		update->abort_cause = reverse_update(update);
	else if ((strncmp(buf, "cleanup", len) == 0 ||
		  strncmp(buf, "cleanup\n", len) == 0) &&
		 update->stage == STAGE_REVERSED)
		kthread_run(maybe_cleanup_ksplice_update_wrapper, update,
			    "ksplice_cleanup_%s", update->kid);

	mutex_unlock(&module_mutex);
	set_all_modules_text_ro();
	return len;
}

static ssize_t debug_show(struct update *update, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", update->debug);
}

static ssize_t debug_store(struct update *update, const char *buf, size_t len)
{
	unsigned long l;
	int ret = strict_strtoul(buf, 10, &l);
	if (ret != 0)
		return ret;
	update->debug = l;
	return len;
}

static ssize_t partial_show(struct update *update, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n", update->partial);
}

static ssize_t partial_store(struct update *update, const char *buf, size_t len)
{
	unsigned long l;
	int ret = strict_strtoul(buf, 10, &l);
	if (ret != 0)
		return ret;
	update->partial = l;
	return len;
}

static struct update_attribute stage_attribute =
	__ATTR(stage, 0600, stage_show, stage_store);
static struct update_attribute abort_cause_attribute =
	__ATTR(abort_cause, 0400, abort_cause_show, NULL);
static struct update_attribute debug_attribute =
	__ATTR(debug, 0600, debug_show, debug_store);
static struct update_attribute partial_attribute =
	__ATTR(partial, 0600, partial_show, partial_store);
static struct update_attribute conflict_attribute =
	__ATTR(conflicts, 0400, conflict_show, NULL);

static struct attribute *update_attrs[] = {
	&stage_attribute.attr,
	&abort_cause_attribute.attr,
	&debug_attribute.attr,
	&partial_attribute.attr,
	&conflict_attribute.attr,
	NULL
};

static struct kobj_type update_ktype = {
	.sysfs_ops = &update_sysfs_ops,
	.release = update_release,
	.default_attrs = update_attrs,
};

#ifdef KSPLICE_STANDALONE
static int debug;
module_param(debug, int, 0600);
MODULE_PARM_DESC(debug, "Debug level");

extern struct ksplice_system_map ksplice_system_map[], ksplice_system_map_end[];

static struct ksplice_mod_change bootstrap_mod_change = {
	.name = "ksplice_" __stringify(KSPLICE_KID),
	.kid = "init_" __stringify(KSPLICE_KID),
	.target_name = NULL,
	.target = NULL,
	.map_printk = MAP_PRINTK,
	.new_code_mod = THIS_MODULE,
	.new_code.system_map = ksplice_system_map,
	.new_code.system_map_end = ksplice_system_map_end,
};

static int __my_set_all_modules_text_rw(struct ksplice_mod_change *change)
{
#ifdef CONFIG_DEBUG_SET_MODULE_RONX
	typeof(&set_all_modules_text_rw) fun;
	LIST_HEAD(vals);
	abort_t ret;

	ret = add_system_map_candidates(change, change->new_code.system_map,
			change->new_code.system_map_end,
			"set_all_modules_text_rw", &vals);
	if (ret != OK)
		return -EIO;
	fun = list_entry(vals.next, struct candidate_val, list)->val;
	release_vals(&vals);

	fun();
#else
	/*
	 * It's an inline, no problem to call it directly.
	 * It should be a nop though.
	 */
	set_all_modules_text_rw();
#endif
	return 0;
}
#endif /* KSPLICE_STANDALONE */

static int init_ksplice(void)
{
#ifdef KSPLICE_STANDALONE
	struct ksplice_mod_change *change = &bootstrap_mod_change;
	int ret;

	change->update = init_ksplice_update(change->kid);
	sort(change->new_code.system_map,
	     change->new_code.system_map_end - change->new_code.system_map,
	     sizeof(struct ksplice_system_map), compare_system_map, NULL);
	if (change->update == NULL)
		return -ENOMEM;
	add_to_update(change, change->update);

	/* we can call it directly even after apply_relocs */
	ret = __my_set_all_modules_text_rw(change);
	if (ret) {
		/* FIXME leak */
		return ret;
	}
	change->update->debug = debug;
	change->update->abort_cause =
	    apply_relocs(change, ksplice_init_relocs, ksplice_init_relocs_end);
	set_all_modules_text_ro();

	if (change->update->abort_cause == OK)
		bootstrapped = true;
	cleanup_ksplice_update(bootstrap_mod_change.update);
#else /* !KSPLICE_STANDALONE */
	ksplice_kobj = kobject_create_and_add("ksplice", kernel_kobj);
	if (ksplice_kobj == NULL)
		return -ENOMEM;
#endif /* KSPLICE_STANDALONE */
	return 0;
}

static void cleanup_ksplice(void)
{
#ifndef KSPLICE_STANDALONE
	kobject_put(ksplice_kobj);
#endif /* KSPLICE_STANDALONE */
}

module_init(init_ksplice);
module_exit(cleanup_ksplice);

MODULE_AUTHOR("Ksplice, Inc.");
MODULE_DESCRIPTION("Ksplice rebootless update system");
#ifdef KSPLICE_VERSION
MODULE_VERSION(KSPLICE_VERSION);
#endif
MODULE_LICENSE("GPL v2");
