/*  This file is based in part on objcopy.c from GNU Binutils v2.17.
 *
 *  Copyright (C) 1991-2006  Free Software Foundation, Inc.
 *  Copyright (C) 2007-2009  Ksplice, Inc.
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

/* objmanip performs various object file manipulations for Ksplice.  Its first
 * two arguments are always an input object file and an output object file.
 *
 * - keep-new-code: "objmanip <post.o> <out.o> keep-new-code <pre.o> <kid>"
 *
 * This mode prepares the object file to be installed as a ksplice update.  The
 * kid argument is the ksplice id string for the ksplice update being built.
 *
 * - keep-old-code: "objmanip <pre.o> <out.o> keep-old-code"
 *
 * This mode prepares the object file to be used for run-pre matching.  This
 * involves replacing all ELF relocations with ksplice relocations and
 * writing ksplice_section structures for each ELF text or data section.
 *
 * - rmsyms mode: "objmanip <in.o> <out.o> rmsyms
 *
 * In this mode, any ELF relocations involving the list of symbol names given on
 * standard input are replaced with ksplice relocations.  This is used only
 * for KSPLICE_STANDALONE.
 *
 * - finalize mode: "objmanip <in.o> <out.o> finalize"
 *
 * In this mode, any ELF relocations to undefined symbols are replaced with
 * ksplice relocations.
 */

/* Always define KSPLICE_STANDALONE, even if you're using integrated Ksplice.
   objmanip won't compile without it. */
#define KSPLICE_STANDALONE

#define _GNU_SOURCE
#include "objcommon.h"
#include "kmodsrc/ksplice.h"
#include "kmodsrc/offsets.h"
#include "ksplice-patch/ksplice-patch.h"
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define KSPLICE_SYMBOL_STR "KSPLICE_SYMBOL_"

#define symbol_init(sym) *(sym) = (asymbol *)NULL
DEFINE_HASH_TYPE(asymbol *, symbol_hash, symbol_hash_init, symbol_hash_free,
		 symbol_hash_lookup, symbol_init);

DECLARE_VEC_TYPE(const char *, str_vec);

DECLARE_VEC_TYPE(unsigned long, ulong_vec);

#define bool_init(b) *(b) = false
DEFINE_HASH_TYPE(bool, bool_hash, bool_hash_init, bool_hash_free,
		 bool_hash_lookup, bool_init);

#define ulong_init(x) *(x) = 0
DEFINE_HASH_TYPE(unsigned long, ulong_hash, ulong_hash_init,
		 ulong_hash_free, ulong_hash_lookup, ulong_init);

void do_keep_new_code(struct superbfd *isbfd, const char *pre);
void do_keep_old_code(struct superbfd *isbfd);
void do_finalize(struct superbfd *isbfd);
void do_rmsyms(struct superbfd *isbfd);

bool relocs_equal(struct supersect *old_src_ss, struct supersect *new_src_ss,
		  arelent *old_reloc, arelent *new_reloc);
bfd_vma non_dst_mask(struct supersect *ss, arelent *reloc);
bool all_relocs_equal(struct span *old_span, struct span *new_span);
static bool part_of_reloc(struct supersect *ss, unsigned long addr);
static bool nonrelocs_equal(struct span *old_span, struct span *new_span);
static void handle_section_symbol_renames(struct superbfd *oldsbfd,
					  struct superbfd *newsbfd);
static void compute_entry_points(struct superbfd *sbfd);
static void copy_patched_entry_points(struct superbfd *oldsbfd,
				      struct superbfd *newsbfd);

enum supersect_type supersect_type(struct supersect *ss);
void initialize_supersect_types(struct superbfd *sbfd);
static void initialize_spans(struct superbfd *sbfd);
static void initialize_string_spans(struct supersect *ss);
static void initialize_table_spans(struct superbfd *sbfd,
				   struct table_section *s);
static void initialize_table_section_spans(struct superbfd *sbfd);
static void initialize_ksplice_call_spans(struct supersect *ss);
struct span *reloc_target_span(struct supersect *ss, arelent *reloc);
static struct span *span_offset_target_span(struct span *span, int offset);
static bfd_vma reloc_target_offset(struct supersect *ss, arelent *reloc);
struct span *find_span(struct supersect *ss, bfd_size_type address);
void remove_unkept_spans(struct superbfd *sbfd);
void compute_span_shifts(struct superbfd *sbfd);
static struct span *new_span(struct supersect *ss, bfd_vma start, bfd_vma size);
static bool is_table_section(const char *name, bool consider_other,
			     bool consider_crc);
const struct table_section *get_table_section(const char *name);
void mangle_section_name(struct superbfd *sbfd, const char *name);

void rm_relocs(struct superbfd *isbfd);
void rm_some_relocs(struct supersect *ss);
void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc);
static void write_ksplice_reloc_howto(struct supersect *ss, const
				      struct ksplice_reloc_howto *const *addr,
				      reloc_howto_type *howto,
				      enum ksplice_reloc_howto_type type);
static void write_ksplice_date_reloc(struct supersect *ss, unsigned long offset,
				     const char *str,
				     enum ksplice_reloc_howto_type type);
static void write_ksplice_patch_reloc(struct supersect *ss,
				      const char *sectname, unsigned long *addr,
				      bfd_size_type size, const char *label,
				      long addend);
static void write_ksplice_nonreloc_howto(struct supersect *ss,
					 const struct ksplice_reloc_howto
					 *const *addr,
					 enum ksplice_reloc_howto_type type,
					 int size);
static void write_date_relocs(struct superbfd *sbfd, const char *str,
			      enum ksplice_reloc_howto_type type);
static void write_table_relocs(struct superbfd *sbfd, const char *sectname,
			       enum ksplice_reloc_howto_type type);
static void write_ksplice_table_reloc(struct supersect *ss,
				      unsigned long address,
				      const char *label,
				      enum ksplice_reloc_howto_type type);
void load_ksplice_symbol_offsets(struct superbfd *sbfd);
void write_canary(struct supersect *ss, int offset, bfd_size_type size,
		  bfd_vma dst_mask);
static void write_ksplice_section(struct span *span);
void write_ksplice_patches(struct superbfd *sbfd, struct span *span);
void write_ksplice_patch(struct superbfd *sbfd, struct span *span,
			 const char *label, long offset);
void *write_patch_storage(struct supersect *ss, struct ksplice_patch *patch,
			  size_t size, struct supersect **data_ssp);
void write_ksplice_deleted_patch(struct superbfd *sbfd, const char *name,
				 const char *label, const char *sectname,
				 long offset);
static void write_bugline_patches(struct superbfd *sbfd);
asymbol **make_undefined_symbolp(struct superbfd *sbfd, const char *name);
void filter_table_sections(struct superbfd *isbfd);
void filter_table_section(struct superbfd *sbfd, const struct table_section *s);
void keep_referenced_sections(struct superbfd *sbfd);
void mark_precallable_spans(struct superbfd *sbfd);
bfd_boolean copy_object(bfd *ibfd, bfd *obfd);
void setup_section(bfd *ibfd, asection *isection, void *obfdarg);
static void setup_new_section(bfd *obfd, struct supersect *ss);
static void write_section(bfd *obfd, asection *osection, void *arg);
static void delete_obsolete_relocs(struct supersect *ss);
void mark_symbols_used_in_relocations(bfd *abfd, asection *isection,
				      void *ignored);
static void ss_mark_symbols_used_in_relocations(struct supersect *ss);
void filter_symbols(bfd *ibfd, bfd *obfd, struct asymbolp_vec *osyms,
		    struct asymbolp_vec *isyms);
static bool deleted_table_section_symbol(bfd *abfd, asymbol *sym);
struct supersect *__attribute((format(printf, 2, 3)))
make_section(struct superbfd *sbfd, const char *fmt, ...);
void __attribute__((format(printf, 3, 4)))
write_string(struct supersect *ss, const char **addr, const char *fmt, ...);
void write_ksplice_export(struct superbfd *sbfd, struct span *span, bool del);
void write_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		 bfd_vma offset);
arelent *create_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		      bfd_vma offset);
static void foreach_symbol_pair(struct superbfd *oldsbfd, struct superbfd *newsbfd,
				void (*fn)(struct span *old_span,
					   asymbol *oldsym,
					   struct span *new_span,
					   asymbol *newsym));
static void check_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym);
static void match_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym);
static void match_symbol_spans(struct span *old_span, asymbol *oldsym,
			       struct span *new_span, asymbol *newsym);
static void match_table_spans(struct span *old_span, struct span *new_span);
static void match_other_spans(struct span *old_span, struct span *new_span);

static struct span *get_crc_span(struct span *span,
				 const struct table_section *ts);
static void foreach_span_pair(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd,
			      void (*fn)(struct span *old_span,
					 struct span *new_span));
static void match_spans_by_label(struct span *old_span, struct span *new_span);
static void match_string_spans(struct span *old_span, struct span *new_span);
static void mark_new_spans(struct superbfd *sbfd);
static void handle_deleted_spans(struct superbfd *oldsbfd,
				 struct superbfd *newsbfd);
static void unmatch_addr_spans(struct span *old_span, struct span *new_span,
			       const struct table_section *ts);
static void compare_matched_spans(struct superbfd *newsbfd);
static void compare_spans(struct span *old_span, struct span *new_span);
static void update_nonzero_offsets(struct superbfd *sbfd);
static void handle_nonzero_offset_relocs(struct supersect *ss);
static void keep_span(struct span *span);

static void init_objmanip_superbfd(struct superbfd *sbfd);
static const char *label_lookup(struct superbfd *sbfd, asymbol *sym);
static void label_map_set(struct superbfd *sbfd, const char *oldlabel,
			  const char *label);
static void print_label_changes(struct superbfd *sbfd);
static void init_label_map(struct superbfd *sbfd);
static void change_initial_label(struct span *span, const char *label);
static asymbol **symbolp_scan(struct supersect *ss, bfd_vma value);
static void init_csyms(struct superbfd *sbfd);
static void init_callers(struct superbfd *sbfd);
static asymbol *canonical_symbol(struct superbfd *sbfd, asymbol *sym);
static asymbol **canonical_symbolp(struct superbfd *sbfd, asymbol *sym);
static char *static_local_symbol(struct superbfd *sbfd, asymbol *sym);
static char *symbol_label(struct superbfd *sbfd, asymbol *sym);

int verbose = 0;
#define debug_(sbfd, level, fmt, ...)					\
	do {								\
		if (verbose >= (level))					\
			printf("%s: " fmt, (sbfd)->abfd->filename,	\
			       ## __VA_ARGS__);				\
	} while (0)
#define debug0(sbfd, fmt, ...) debug_(sbfd, 0, fmt, ## __VA_ARGS__)
#define debug1(sbfd, fmt, ...) debug_(sbfd, 1, fmt, ## __VA_ARGS__)
#define err(sbfd, fmt, ...)						\
	do {								\
		fprintf(stderr, "%s: " fmt, (sbfd)->abfd->filename,	\
			## __VA_ARGS__);				\
	} while (0)

struct str_vec delsects;
struct asymbolp_vec extract_syms;
bool changed;

struct ksplice_config *config;

const char *modestr, *kid, *finalize_target = NULL;
bool write_output = true;

struct superbfd *offsets_sbfd = NULL;

#define mode(str) strstarts(modestr, str)

DECLARE_VEC_TYPE(unsigned long, addr_vec);
DEFINE_HASH_TYPE(struct addr_vec, addr_vec_hash,
		 addr_vec_hash_init, addr_vec_hash_free, addr_vec_hash_lookup,
		 vec_init);
struct addr_vec_hash system_map;

struct bool_hash system_map_written;
struct ulong_hash ksplice_symbol_offset;
struct ulong_hash ksplice_howto_offset;
struct ulong_hash ksplice_string_offset;

void load_system_map()
{
	const char *config_dir = getenv("KSPLICE_CONFIG_DIR");
	assert(config_dir);
	FILE *fp = fopen(strprintf("%s/System.map", config_dir), "r");
	assert(fp);
	addr_vec_hash_init(&system_map);
	unsigned long addr;
	char type;
	char *sym;
	while (fscanf(fp, "%lx %c %as\n", &addr, &type, &sym) == 3)
		*vec_grow(addr_vec_hash_lookup(&system_map, sym, TRUE),
			  1) = addr;
	fclose(fp);
}

void load_ksplice_symbol_offsets(struct superbfd *sbfd)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd,
						 ".ksplice_symbols");
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);

	struct ksplice_symbol *ksym;
	for (ksym = ss->contents.data;
	     (void *)ksym < ss->contents.data + ss->contents.size; ksym++) {
		const char *label = read_string(ss, &ksym->label);
		unsigned long *ksymbol_offp =
		    ulong_hash_lookup(&ksplice_symbol_offset, label, TRUE);
		*ksymbol_offp = addr_offset(ss, ksym);
	}
}

void load_offsets()
{
	char *kmodsrc = getenv("KSPLICE_KMODSRC");
	assert(kmodsrc != NULL);
	bfd *offsets_bfd = bfd_openr(strprintf("%s/offsets.o", kmodsrc), NULL);
	assert(offsets_bfd != NULL);
	char **matching;
	assert(bfd_check_format_matches(offsets_bfd, bfd_object, &matching));
	offsets_sbfd = fetch_superbfd(offsets_bfd);

	asection *config_sect = bfd_get_section_by_name(offsets_sbfd->abfd,
							".ksplice_config");
	struct supersect *config_ss =
	    fetch_supersect(offsets_sbfd, config_sect);

	config = config_ss->contents.data;
}

void load_options(struct superbfd *sbfd)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd,
						 ".ksplice_options");
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);
	const struct ksplice_option *opt;
	for (opt = ss->contents.data;
	     (void *)opt < ss->contents.data + ss->contents.size; opt++) {
		if (opt->type == KSPLICE_OPTION_ASSUME_RODATA) {
			arelent *reloc = find_reloc(ss, &opt->target);
			assert(reloc != NULL);
			struct span *span = reloc_target_span(ss, reloc);
			assert(span != NULL);
			assert(span->ss->type == SS_TYPE_DATA);
			assert(span->start == 0 &&
			       span->size == span->ss->contents.size);
			span->ss->type = SS_TYPE_RODATA;
		} else if (opt->type == KSPLICE_OPTION_MATCH_DATA_EARLY) {
			arelent *reloc = find_reloc(ss, &opt->target);
			assert(reloc != NULL);
			struct span *span = reloc_target_span(ss, reloc);
			assert(span != NULL);
			assert(span->ss->type == SS_TYPE_DATA);
			assert(span->start == 0 &&
			       span->size == span->ss->contents.size);
			span->ss->match_data_early = true;
		} else {
			err(sbfd, "Unrecognized Ksplice option %d\n",
			    opt->type);
			DIE;
		}
	}
}

bool matchable_data_section(struct supersect *ss)
{
	if (ss->type == SS_TYPE_STRING)
		return true;
	if (ss->type == SS_TYPE_RODATA)
		return true;
	if (ss->type == SS_TYPE_DATA && ss->relocs.size != 0)
		return true;
	if (ss->type == SS_TYPE_EXPORT)
		return true;
	if (ss->type == SS_TYPE_BUGTABLE)
		return true;
	return false;
}

bool unchangeable_section(struct supersect *ss)
{
	if (ss->type == SS_TYPE_DATA)
		return true;
	if (ss->type == SS_TYPE_IGNORED && !strstarts(ss->name, ".debug") &&
	    strcmp(ss->name, "__ksymtab_strings") != 0)
		return true;
	return false;
}

int main(int argc, char *argv[])
{
	if (getenv("KSPLICE_VERBOSE") != NULL)
		verbose = atoi(getenv("KSPLICE_VERBOSE"));

	bfd_init();
	bfd *ibfd = bfd_openr(argv[1], NULL);
	assert(ibfd);

	char **matching;
	if (bfd_check_format_matches(ibfd, bfd_archive, &matching) &&
	    bfd_openr_next_archived_file(ibfd, NULL) == NULL)
		return 66; /* empty archive */
	assert(bfd_check_format_matches(ibfd, bfd_object, &matching));

	const char *output_target = bfd_get_target(ibfd);

	load_system_map();
	load_offsets();

	bool_hash_init(&system_map_written);
	ulong_hash_init(&ksplice_symbol_offset);
	ulong_hash_init(&ksplice_howto_offset);
	ulong_hash_init(&ksplice_string_offset);

	struct superbfd *isbfd = fetch_superbfd(ibfd);

	modestr = argv[3];
	if (mode("finalize"))
		finalize_target = argv[4];
	init_objmanip_superbfd(isbfd);
	if (mode("keep-new-code")) {
		kid = argv[5];
		do_keep_new_code(isbfd, argv[4]);
	} else if (mode("keep-old-code")) {
		do_keep_old_code(isbfd);
	} else if (mode("finalize")) {
		do_finalize(isbfd);
	} else if (mode("rmsyms")) {
		do_rmsyms(isbfd);
	}

	if (write_output) {
		bfd *obfd = bfd_openw(argv[2], output_target);
		assert(obfd);
		copy_object(ibfd, obfd);
		assert(bfd_close(obfd));
	}

	if (offsets_sbfd != NULL)
		assert(bfd_close(offsets_sbfd->abfd));
	assert(bfd_close(ibfd));
	return EXIT_SUCCESS;
}

void do_keep_new_code(struct superbfd *isbfd, const char *pre)
{
	struct bfd *prebfd = bfd_openr(pre, NULL);
	assert(prebfd != NULL);
	char **matching;
	assert(bfd_check_format_matches(prebfd, bfd_object, &matching));

	struct superbfd *presbfd = fetch_superbfd(prebfd);
	init_objmanip_superbfd(presbfd);

	foreach_symbol_pair(presbfd, isbfd, match_global_symbols);
	debug1(isbfd, "Matched global\n");
	foreach_span_pair(presbfd, isbfd, match_string_spans);
	debug1(isbfd, "Matched string spans\n");
	foreach_symbol_pair(presbfd, isbfd, match_symbol_spans);
	debug1(isbfd, "Matched by name\n");
	foreach_span_pair(presbfd, isbfd, match_spans_by_label);
	debug1(isbfd, "Matched by label\n");
	foreach_span_pair(presbfd, isbfd, match_table_spans);
	debug1(isbfd, "Matched table spans\n");
	foreach_span_pair(presbfd, isbfd, match_other_spans);
	debug1(isbfd, "Matched other spans\n");

	do {
		changed = false;
		compare_matched_spans(isbfd);
		update_nonzero_offsets(isbfd);
		mark_new_spans(isbfd);
	} while (changed);
	vec_init(&delsects);

	foreach_symbol_pair(presbfd, isbfd, check_global_symbols);

	handle_deleted_spans(presbfd, isbfd);
	handle_section_symbol_renames(presbfd, isbfd);

	copy_patched_entry_points(presbfd, isbfd);

	assert(bfd_close(prebfd));

	do {
		changed = false;
		mark_precallable_spans(isbfd);
	} while (changed);

	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		ss->keep = false;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (strstarts(ss->name, ".ksplice_options"))
				span->keep = false;
			else if (span->new || span->patch || span->datapatch)
				keep_span(span);
			else
				span->keep = false;
			if (span->patch && span->precallable) {
				err(isbfd, "Patched span %s can be reached "
				    "by a precall function\n", span->label);
				DIE;
			}
		}
	}

	print_label_changes(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->patch || span->bugpatch || span->datapatch)
				debug0(isbfd, "Patching span %s\n",
				       span->label);
		}
	}

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->new)
				debug0(isbfd, "New span %s\n", span->label);
		}
	}

	write_output = false;
	const char **sectname;
	for (sectname = delsects.data;
	     sectname < delsects.data + delsects.size; sectname++) {
		write_output = true;
		debug0(isbfd, "Deleted section: %s\n", *sectname);
	}

	filter_table_sections(isbfd);

	compute_span_shifts(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (ss->type == SS_TYPE_KSPLICE_CALL)
			continue;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->keep || span->bugpatch)
				write_output = true;
			if (span->patch || span->new || span->datapatch)
				write_ksplice_section(span);
			if (span->patch || span->datapatch)
				write_ksplice_patches(isbfd, span);
			if (ss->type == SS_TYPE_EXPORT && span->new)
				write_ksplice_export(isbfd, span, false);
		}
	}

	write_bugline_patches(isbfd);
	rm_relocs(isbfd);
	remove_unkept_spans(isbfd);
}

void do_keep_old_code(struct superbfd *isbfd)
{
	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		ss->keep = false;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			span->keep = false;
			if (ss->type == SS_TYPE_TEXT &&
			    !strstarts(ss->name, ".fixup"))
				keep_span(span);
			if (ss->type == SS_TYPE_EXPORT)
				keep_span(span);
		}
	}

	asymbol **symp;
	for (symp = isbfd->syms.data;
	     symp < isbfd->syms.data + isbfd->syms.size; symp++) {
		asymbol *sym = *symp;
		if (!bfd_is_const_section(sym->section) &&
		    (sym->flags & BSF_GLOBAL) != 0) {
			struct supersect *sym_ss =
			    fetch_supersect(isbfd, sym->section);
			if (sym->value == sym_ss->contents.size)
				continue;
			struct span *span = find_span(sym_ss, sym->value);
			assert(span != NULL);
			if (sym_ss->type != SS_TYPE_IGNORED)
				keep_span(span);
		}
	}

	do {
		changed = false;
		keep_referenced_sections(isbfd);
	} while (changed);

	filter_table_sections(isbfd);
	compute_span_shifts(isbfd);

	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		asymbol *sym = canonical_symbol(isbfd, sect->symbol);
		if (sym == NULL)
			continue;
		if ((sym->flags & BSF_WEAK) != 0)
			continue;
		if (bfd_get_section_size(sect) == 0)
			continue;
		if (!ss->keep)
			continue;
		if (ss->type != SS_TYPE_TEXT && !matchable_data_section(ss))
			continue;

		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->keep)
				write_ksplice_section(span);
		}
	}

	write_table_relocs(isbfd, "__bug_table", KSPLICE_HOWTO_BUG);
	write_table_relocs(isbfd, "__ex_table", KSPLICE_HOWTO_EXTABLE);
	rm_relocs(isbfd);
	remove_unkept_spans(isbfd);

	mangle_section_name(isbfd, "__markers");
	mangle_section_name(isbfd, "__tracepoints");
	mangle_section_name(isbfd, "__ex_table");
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (ss->type == SS_TYPE_EXPORT)
			mangle_section_name(isbfd, ss->name);
	}
}

void do_finalize(struct superbfd *isbfd)
{
	load_ksplice_symbol_offsets(isbfd);
	asection *sect;
	for (sect = isbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(isbfd, sect);
		if (ss->type == SS_TYPE_EXIT) {
			struct span *span;
			for (span = ss->spans.data;
			     span < ss->spans.data + ss->spans.size; span++)
				span->keep = false;
			ss->keep = false;
		}
	}
	write_date_relocs(isbfd, "<{DATE...}>", KSPLICE_HOWTO_DATE);
	write_date_relocs(isbfd, "<{TIME}>", KSPLICE_HOWTO_TIME);
	rm_relocs(isbfd);
}

void do_rmsyms(struct superbfd *isbfd)
{
	asection *extract_sect = bfd_get_section_by_name(isbfd->abfd,
							 ".ksplice_extract");
	if (extract_sect != NULL) {
		struct supersect *extract_ss = fetch_supersect(isbfd,
							       extract_sect);
		arelent **relocp;
		for (relocp = extract_ss->relocs.data;
		     relocp < extract_ss->relocs.data + extract_ss->relocs.size;
		     relocp++) {
			asymbol *sym = *(*relocp)->sym_ptr_ptr;
			if (bfd_is_und_section(sym->section)) {
				debug1(isbfd, "extracting symbol %s\n",
				       sym->name);
				*vec_grow(&extract_syms, 1) = sym;
			}
		}
	}

	rm_relocs(isbfd);
}

void match_spans(struct span *old_span, struct span *new_span)
{
	struct superbfd *sbfd = new_span->ss->parent;
	if (old_span->match == new_span && new_span->match == old_span)
		return;
	if (old_span->match != NULL) {
		err(sbfd, "Matching conflict: old %s: %s != %s\n",
		    old_span->label, old_span->match->label, new_span->label);
		DIE;
	}
	if (new_span->match != NULL) {
		err(sbfd, "Matching conflict: new %s: %s != %s\n",
		    new_span->label, new_span->match->label, old_span->label);
		DIE;
	}
	old_span->match = new_span;
	new_span->match = old_span;
	debug1(sbfd, "Matched old %s to new %s\n", old_span->label,
	       new_span->label);
	if (old_span->ss->type != new_span->ss->type &&
	    old_span->ss->type == new_span->ss->orig_type)
		old_span->ss->type = new_span->ss->type;

	const struct table_section *ts = get_table_section(old_span->ss->name);
	if (ts == NULL || !ts->has_addr || ts->other_sect == NULL)
		return;
	struct span *old_sym_span =
	    span_offset_target_span(old_span, ts->other_offset);
	struct span *new_sym_span =
	    span_offset_target_span(new_span, ts->other_offset);
	assert(old_sym_span != NULL && new_sym_span != NULL);
	match_spans(old_sym_span, new_sym_span);
}

void unmatch_span(struct span *old_span)
{
	struct span *new_span = old_span->match;
	old_span->match = NULL;
	new_span->match = NULL;

	new_span->bugpatch = false;

	if (old_span->ss->type == SS_TYPE_SPECIAL) {
		const struct table_section *ts =
		    get_table_section(old_span->ss->name);
		if (ts != NULL && ts->has_addr)
			unmatch_addr_spans(old_span, new_span, ts);
	}

	new_span->patch = false;
	new_span->bugpatch = false;
	new_span->datapatch = false;

	changed = true;
}

static void match_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym)
{
	if (newsym == NULL ||
	    (oldsym->flags & BSF_GLOBAL) == 0 ||
	    (newsym->flags & BSF_GLOBAL) == 0)
		return;
	match_spans(old_span, new_span);
}

static void check_global_symbols(struct span *old_span, asymbol *oldsym,
				 struct span *new_span, asymbol *newsym)
{
	if ((oldsym->flags & BSF_GLOBAL) == 0 ||
	    (newsym != NULL && (newsym->flags & BSF_GLOBAL) == 0))
		return;
	if (old_span->ss->type == SS_TYPE_IGNORED)
		return;
	if (old_span->match != new_span) {
		if (new_span != NULL)
			err(new_span->ss->parent,
			    "Global symbol span mismatch: %s %s/%s\n",
			    oldsym->name, old_span->label, new_span->label);
		else
			err(old_span->ss->parent,
			    "Global symbol span mismatch: %s %s/NULL\n",
			    oldsym->name, old_span->label);
		DIE;
	}
}

static void foreach_symbol_pair(struct superbfd *oldsbfd, struct superbfd *newsbfd,
				void (*fn)(struct span *old_span,
					   asymbol *oldsym,
					   struct span *new_span,
					   asymbol *newsym))
{
	asymbol **oldsymp, **newsymp;
	for (oldsymp = oldsbfd->syms.data;
	     oldsymp < oldsbfd->syms.data + oldsbfd->syms.size; oldsymp++) {
		asymbol *oldsym = *oldsymp;
		if ((oldsym->flags & BSF_DEBUGGING) != 0 ||
		    bfd_is_const_section(oldsym->section))
			continue;

		struct supersect *old_ss =
		    fetch_supersect(oldsbfd, oldsym->section);
		if (old_ss->type == SS_TYPE_SPECIAL ||
		    old_ss->type == SS_TYPE_EXPORT)
			continue;

		struct span *old_span = find_span(old_ss, oldsym->value);
		if (old_span == NULL) {
			err(oldsbfd, "Could not find span for %s\n",
			    oldsym->name);
			DIE;
		}

		bool found = false;

		for (newsymp = newsbfd->syms.data;
		     newsymp < newsbfd->syms.data + newsbfd->syms.size;
		     newsymp++) {
			asymbol *newsym = *newsymp;
			if ((newsym->flags & BSF_DEBUGGING) != 0 ||
			    bfd_is_const_section(newsym->section))
				continue;
			if (strcmp(oldsym->name, newsym->name) != 0)
				continue;

			struct supersect *new_ss =
			    fetch_supersect(newsbfd, newsym->section);
			if (old_ss->type != new_ss->type &&
			    old_ss->type != new_ss->orig_type)
				continue;

			assert(!found);
			found = true;

			struct span *new_span =
			    find_span(new_ss, newsym->value);
			if (new_span == NULL) {
				err(newsbfd, "Could not find span for %s\n",
				    newsym->name);
				DIE;
			}
			fn(old_span, oldsym, new_span, newsym);
		}

		if (!found)
			fn(old_span, oldsym, NULL, NULL);
	}
}

static void match_symbol_spans(struct span *old_span, asymbol *oldsym,
			       struct span *new_span, asymbol *newsym)
{
	if (newsym == NULL)
		return;
	if (old_span->ss->type == SS_TYPE_SPECIAL)
		return;
	if (static_local_symbol(old_span->ss->parent, oldsym) ||
	    static_local_symbol(new_span->ss->parent, newsym))
		return;
	if (old_span->match == NULL && new_span->match == NULL)
		match_spans(old_span, new_span);
}

static void match_spans_by_label(struct span *old_span, struct span *new_span)
{
	if (old_span->ss->type == SS_TYPE_STRING ||
	    (is_table_section(old_span->ss->name, true, false) &&
	     !is_table_section(old_span->ss->name, false, false)))
		return;
	if (strcmp(old_span->label, new_span->label) == 0)
		match_spans(old_span, new_span);
}

static void match_string_spans(struct span *old_span, struct span *new_span)
{
	if (old_span->ss->type != SS_TYPE_STRING ||
	    strcmp(old_span->ss->name, new_span->ss->name) != 0)
		return;
	if (strcmp((char *)old_span->ss->contents.data + old_span->start,
		   (char *)new_span->ss->contents.data + new_span->start) == 0)
		match_spans(old_span, new_span);
}

static void foreach_span_pair(struct superbfd *oldsbfd,
			      struct superbfd *newsbfd,
			      void (*fn)(struct span *old_span,
					 struct span *new_span))
{
	asection *oldsect, *newsect;
	struct supersect *oldss, *newss;
	struct span *old_span, *new_span;
	for (newsect = newsbfd->abfd->sections; newsect != NULL;
	     newsect = newsect->next) {
		newss = fetch_supersect(newsbfd, newsect);
		for (oldsect = oldsbfd->abfd->sections; oldsect != NULL;
		     oldsect = oldsect->next) {
			oldss = fetch_supersect(oldsbfd, oldsect);
			if (oldss->type != newss->type)
				continue;
			for (new_span = newss->spans.data;
			     new_span < newss->spans.data + newss->spans.size;
			     new_span++) {
				for (old_span = oldss->spans.data;
				     old_span < oldss->spans.data +
				     oldss->spans.size; old_span++)
					fn(old_span, new_span);
			}
		}
	}
}

static void mark_new_spans(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_SPECIAL || ss->type == SS_TYPE_IGNORED)
			continue;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match == NULL)
				span->new = true;
		}
	}
}

static void handle_deleted_spans(struct superbfd *oldsbfd,
				 struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = oldsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(oldsbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match != NULL)
				continue;
			if (ss->type == SS_TYPE_EXPORT) {
				*vec_grow(&delsects, 1) = span->label;
				write_ksplice_export(newsbfd, span, true);
			} else if (ss->type == SS_TYPE_TEXT) {
				*vec_grow(&delsects, 1) = span->label;
				if (span->symbol == NULL)
					DIE;
				write_ksplice_deleted_patch
				    (newsbfd, span->symbol->name, span->label,
				     span->ss->name, 0);
			}
		}
	}
}

static void handle_nonzero_offset_relocs(struct supersect *ss)
{
	struct span *address_span, *target_span;
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		arelent *reloc = *relocp;
		address_span = find_span(ss, reloc->address);
		if (!address_span->new && !address_span->patch)
			continue;

		asymbol *sym = *reloc->sym_ptr_ptr;
		if (bfd_is_const_section(sym->section))
			continue;
		bfd_vma offset = reloc_target_offset(ss, reloc);
		target_span = reloc_target_span(ss, reloc);
		if (sym->value + offset == target_span->start)
			continue;

		if (target_span->ss->type != SS_TYPE_TEXT)
			continue;
		if (target_span->patch)
			continue;

		target_span->patch = true;
		changed = true;
		debug1(ss->parent, "Changing %s because a relocation from sect "
		       "%s has a nonzero offset %lx+%lx into it\n",
		       target_span->label, ss->name, (unsigned long)sym->value,
		       (unsigned long)offset);
	}
}

static void update_nonzero_offsets(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_SPECIAL || ss->type == SS_TYPE_IGNORED)
			continue;
		handle_nonzero_offset_relocs(ss);
	}
}

static void unmatch_addr_spans(struct span *old_span, struct span *new_span,
			       const struct table_section *ts)
{
	struct span *old_sym_span =
	    span_offset_target_span(old_span, ts->addr_offset);
	struct span *new_sym_span =
	    span_offset_target_span(new_span, ts->addr_offset);
	assert(old_sym_span != NULL && new_sym_span != NULL);
	if (old_sym_span->match == new_sym_span &&
	    new_sym_span->match == old_sym_span &&
	    !(new_sym_span->patch && new_sym_span->ss->type == SS_TYPE_TEXT)) {
		if (old_sym_span->ss->type == SS_TYPE_TEXT) {
			debug1(new_span->ss->parent, "Patching %s due "
			       "to relocations from special section %s\n",
			       new_sym_span->label, new_span->label);
			new_sym_span->patch = true;
		} else {
			debug1(new_span->ss->parent, "Unmatching %s and %s due "
			       "to relocations from special section %s/%s\n",
			       old_sym_span->label, new_sym_span->label,
			       old_span->label, new_span->label);
			unmatch_span(old_sym_span);
		}
		changed = true;
	}
}

static void compare_spans(struct span *old_span, struct span *new_span)
{
	struct superbfd *newsbfd = new_span->ss->parent;

	bool nonrelocs_match = nonrelocs_equal(old_span, new_span);
	bool relocs_match = all_relocs_equal(old_span, new_span);
	if (nonrelocs_match && relocs_match) {
		const struct table_section *ts =
		    get_table_section(old_span->ss->name);
		if (ts != NULL && ts->crc_sect != NULL) {
			struct span *old_crc_span = get_crc_span(old_span, ts);
			struct span *new_crc_span = get_crc_span(new_span, ts);
			assert(old_crc_span != NULL);
			assert(new_crc_span != NULL);
			if (old_crc_span->match != new_crc_span ||
			    new_crc_span->match != old_crc_span) {
				debug1(newsbfd, "Unmatching %s and %s due to "
				       "nonmatching CRCs\n", old_span->label,
				       new_span->label);
				unmatch_span(old_span);
			}
		}
		return;
	}

	char *reason;
	if (new_span->contents_size != old_span->contents_size)
		reason = "differing sizes";
	else if (!nonrelocs_match)
		reason = "differing contents";
	else
		reason = "differing relocations";

	if (new_span->ss->type == SS_TYPE_TEXT) {
		if (new_span->patch)
			return;
		new_span->patch = true;
		debug1(newsbfd, "Changing %s due to %s\n", new_span->label,
		       reason);
	} else if (old_span->ss->type == SS_TYPE_BUGTABLE &&
		   new_span->ss->type == SS_TYPE_BUGTABLE && relocs_match) {
		if (new_span->bugpatch)
			return;
		debug1(newsbfd, "Changing %s due to %s\n",
		       new_span->label, reason);
		new_span->bugpatch = true;
	} else if (new_span->ss->type == SS_TYPE_RODATA &&
		   new_span->contents_size == old_span->contents_size) {
		if (new_span->datapatch)
			return;
		new_span->datapatch = true;
		debug1(newsbfd, "Changing %s in-place due to %s\n",
		       new_span->label, reason);
	} else if (new_span->ss->type == SS_TYPE_STRING &&
		   old_span->ss->type == SS_TYPE_STRING && relocs_match &&
		   strcmp(new_span->ss->contents.data + new_span->start,
			  old_span->ss->contents.data + old_span->start) == 0) {
		return;
	} else {
		debug1(newsbfd, "Unmatching %s and %s due to %s\n",
		       old_span->label, new_span->label, reason);
		unmatch_span(old_span);
	}
	changed = true;
	if (unchangeable_section(new_span->ss))
		err(newsbfd, "warning: ignoring change to nonpatchable "
		    "section %s\n", new_span->ss->name);
}

static void compare_matched_spans(struct superbfd *newsbfd)
{
	asection *sect;
	for (sect = newsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(newsbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match == NULL)
				continue;
			compare_spans(span->match, span);
		}
	}
}

static void handle_section_symbol_renames(struct superbfd *oldsbfd,
					  struct superbfd *newsbfd)
{
	asection *sect;
	struct span *span;
	for (sect = newsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(newsbfd, sect);
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (span->match == NULL)
				continue;
			if (strcmp(span->label, span->match->label) == 0)
				continue;
			if (strcmp(span->orig_label, span->label) != 0 &&
			    strcmp(span->label, span->match->label) != 0)
				DIE;
			if (span->symbol != NULL)
				label_map_set(newsbfd, span->label,
					      span->match->label);
			span->label = span->match->label;
		}
	}
}

static void copy_patched_entry_points(struct superbfd *oldsbfd,
				      struct superbfd *newsbfd)
{
	asection *sect;
	struct span *span;
	for (sect = newsbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(newsbfd, sect);
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (!span->patch)
				continue;
			assert(span->match != NULL);
			vec_init(&span->pre_entry_points);

			struct entry_point *entry;
			for (entry = span->match->entry_points.data;
			     entry < span->match->entry_points.data +
				     span->match->entry_points.size;
			     entry++) {
				struct entry_point *e =
				    vec_grow(&span->pre_entry_points, 1);
				e->name = entry->name != NULL ?
				    strdup(entry->name) : NULL;
				e->label = strdup(entry->label);
				e->offset = entry->offset;
				e->symbol = NULL;
			}
		}
	}
}

static int compare_entry_points(const void *va, const void *vb)
{
	const struct entry_point *a = va, *b = vb;
	if (a->offset < b->offset)
		return -1;
	else if (a->offset > b->offset)
		return 1;
	else
		return 0;
}

static void compute_entry_points(struct superbfd *sbfd)
{
	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if (bfd_is_const_section(sym->section))
			continue;
		struct supersect *old_ss = fetch_supersect(sbfd, sym->section);
		if ((sym->flags & BSF_GLOBAL) == 0)
			continue;
		struct span *span = find_span(old_ss, sym->value);
		struct entry_point *e = vec_grow(&span->entry_points, 1);
		e->label = sym->name;
		e->name = sym->name;
		e->offset = sym->value - span->start;
		e->symbol = sym;
	}

	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			/* First make sure that 0 appears as an entry point */
			bool found_zero = false;
			struct entry_point *entry;
			for (entry = span->entry_points.data;
			     entry < span->entry_points.data +
				     span->entry_points.size;
			     entry++) {
				if (entry->offset == 0)
					found_zero = true;
			}
			if (!found_zero) {
				struct entry_point *e =
				    vec_grow(&span->entry_points, 1);
				e->label = span->label;
				e->name = NULL;
				e->offset = 0;
				e->symbol = span->symbol;
			}

			qsort(span->entry_points.data, span->entry_points.size,
			      sizeof(*span->entry_points.data),
			      compare_entry_points);
		}
	}
}

static bool part_of_reloc(struct supersect *ss, unsigned long addr)
{
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		arelent *reloc = *relocp;
		if (addr >= reloc->address &&
		    addr < reloc->address + bfd_get_reloc_size(reloc->howto))
			return true;
	}
	return false;
}

static bool nonrelocs_equal(struct span *old_span, struct span *new_span)
{
	int i;
	struct supersect *old_ss = old_span->ss, *new_ss = new_span->ss;
	if (old_span->contents_size != new_span->contents_size)
		return false;
	const unsigned char *old = old_ss->contents.data + old_span->start;
	const unsigned char *new = new_ss->contents.data + new_span->start;
	for (i = 0; i < old_span->contents_size; i++) {
		if (old[i] != new[i] &&
		    !(part_of_reloc(old_ss, i + old_span->start) &&
		      part_of_reloc(new_ss, i + new_span->start)))
			return false;
	}
	return true;
}

bool relocs_equal(struct supersect *old_src_ss, struct supersect *new_src_ss,
		  arelent *old_reloc, arelent *new_reloc)
{
	struct superbfd *oldsbfd = old_src_ss->parent;
	struct superbfd *newsbfd = new_src_ss->parent;
	struct span *old_addr_span = find_span(old_src_ss, old_reloc->address);
	struct span *new_addr_span = find_span(new_src_ss, new_reloc->address);

	if (old_reloc->address - old_addr_span->start !=
	    new_reloc->address - new_addr_span->start) {
		debug1(newsbfd, "Section %s/%s has reloc address mismatch at "
		       "%lx\n", old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_reloc->address);
		return false;
	}

	if (old_reloc->howto != new_reloc->howto) {
		debug1(newsbfd, "Section %s/%s has howto type mismatch at "
		       "%lx\n", old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_reloc->address);
		return false;
	}

	if (non_dst_mask(old_src_ss, old_reloc) !=
	    non_dst_mask(new_src_ss, new_reloc)) {
		debug1(newsbfd, "Section %s/%s has contents mismatch at %lx\n",
		       old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_reloc->address);
		return false;
	}

	asymbol *old_sym = *old_reloc->sym_ptr_ptr;
	asymbol *new_sym = *new_reloc->sym_ptr_ptr;
	asection *old_sect = old_sym->section;
	asection *new_sect = new_sym->section;

	bfd_vma old_offset = reloc_target_offset(old_src_ss, old_reloc);
	bfd_vma new_offset = reloc_target_offset(new_src_ss, new_reloc);

	if (bfd_is_und_section(old_sect) || bfd_is_und_section(new_sect)) {
		if (!bfd_is_und_section(new_sect) && old_offset != 0 &&
		    fetch_supersect(newsbfd, new_sect)->type == SS_TYPE_TEXT)
			return false;

		if (!bfd_is_und_section(old_sect) && new_offset != 0 &&
		    fetch_supersect(oldsbfd, old_sect)->type == SS_TYPE_TEXT)
			return false;

		return strcmp(old_sym->name, new_sym->name) == 0 &&
		    old_offset == new_offset;
	}

	if (bfd_is_abs_section(old_sect) && bfd_is_abs_section(new_sect)) {
		if (old_sym->value + old_offset == new_sym->value + new_offset)
			return true;
		debug1(newsbfd, "Differing relocations from %s/%s to ABS "
		       "section: %lx/%lx\n", old_addr_span->label,
		       new_addr_span->label,
		       (unsigned long)(old_sym->value + old_offset),
		       (unsigned long)(new_sym->value + new_offset));
		return false;
	}

	if (bfd_is_const_section(old_sect) || bfd_is_const_section(new_sect))
		DIE;

	struct supersect *old_ss = fetch_supersect(oldsbfd, old_sect);
	struct supersect *new_ss = fetch_supersect(newsbfd, new_sect);
	struct span *old_span = reloc_target_span(old_src_ss, old_reloc);
	struct span *new_span = reloc_target_span(new_src_ss, new_reloc);

	if (old_span->match != new_span || new_span->match != old_span) {
		debug1(newsbfd, "Nonmatching relocs from %s to %s/%s\n",
		       new_src_ss->name, old_span->label, new_span->label);
		return false;
	}

	if (old_sym->value + old_offset - old_span->start !=
	    new_sym->value + new_offset - new_span->start) {
		debug1(newsbfd, "Offsets to %s/%s differ between %s "
		       "and %s: %lx+%lx/%lx+%lx\n", old_ss->name,
		       new_ss->name, old_src_ss->name, new_src_ss->name,
		       (unsigned long)old_sym->value, (unsigned long)old_offset,
		       (unsigned long)new_sym->value,
		       (unsigned long)new_offset);
		return false;
	}

	if ((old_sym->value + old_offset - old_span->start != 0 ||
	     new_sym->value + new_offset - new_span->start != 0) &&
	    new_span->patch) {
		debug1(newsbfd, "Relocation from %s to nonzero offsets "
		       "%lx+%lx/%lx+%lx in changed section %s\n",
		       new_src_ss->name, (unsigned long)old_sym->value,
		       (unsigned long)old_offset, (unsigned long)new_sym->value,
		       (unsigned long)new_offset, new_sym->section->name);
		return false;
	}
	return true;
}

bool all_relocs_equal(struct span *old_span, struct span *new_span)
{
	struct supersect *old_ss = old_span->ss, *new_ss = new_span->ss;
	arelent **old_relocp, **new_relocp;

	for (old_relocp = old_ss->relocs.data;
	     old_relocp < old_ss->relocs.data + old_ss->relocs.size;
	     old_relocp++) {
		if (find_span(old_ss, (*old_relocp)->address) == old_span)
			break;
	}

	for (new_relocp = new_ss->relocs.data;
	     new_relocp < new_ss->relocs.data + new_ss->relocs.size;
	     new_relocp++) {
		if (find_span(new_ss, (*new_relocp)->address) == new_span)
			break;
	}

	for (; old_relocp < old_ss->relocs.data + old_ss->relocs.size &&
	     find_span(old_ss, (*old_relocp)->address) == old_span &&
	     new_relocp < new_ss->relocs.data + new_ss->relocs.size &&
	     find_span(new_ss, (*new_relocp)->address) == new_span;
	     old_relocp++, new_relocp++) {
		if (!relocs_equal(old_ss, new_ss, *old_relocp, *new_relocp))
			return false;
	}

	if ((old_relocp < old_ss->relocs.data + old_ss->relocs.size &&
	     find_span(old_ss, (*old_relocp)->address) == old_span) ||
	    (new_relocp < new_ss->relocs.data + new_ss->relocs.size &&
	     find_span(new_ss, (*new_relocp)->address) == new_span)) {
		debug1(new_ss->parent, "Different reloc count between %s and "
		       "%s\n", old_span->label, new_span->label);
		return false;
	}

	return true;
}

bfd_vma non_dst_mask(struct supersect *ss, arelent *reloc)
{
	int bits = bfd_get_reloc_size(reloc->howto) * 8;
	void *address = ss->contents.data + reloc->address;
	bfd_vma x = bfd_get(bits, ss->parent->abfd, address);
	return x & ~reloc->howto->dst_mask;
}

void rm_relocs(struct superbfd *isbfd)
{
	asection *p;
	for (p = isbfd->abfd->sections; p != NULL; p = p->next) {
		struct supersect *ss = fetch_supersect(isbfd, p);
		bool remove_relocs = ss->keep;

		if (mode("keep") && ss->type == SS_TYPE_SPECIAL)
			remove_relocs = false;

		if (ss->type == SS_TYPE_KSPLICE ||
		    ss->type == SS_TYPE_KSPLICE_CALL)
			remove_relocs = false;
		if (mode("finalize") &&
		    (strstarts(ss->name, ".ksplice_patches") ||
		     strstarts(ss->name, ".ksplice_relocs")))
			remove_relocs = true;

		if (remove_relocs)
			rm_some_relocs(ss);
	}
}

void rm_some_relocs(struct supersect *ss)
{
	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	arelent **relocp;
	for (relocp = orig_relocs.data;
	     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
		bool rm_reloc = false;
		asymbol *sym_ptr = *(*relocp)->sym_ptr_ptr;

		if (mode("rmsyms") && bfd_is_und_section(sym_ptr->section)) {
			asymbol **esymp;
			for (esymp = extract_syms.data;
			     esymp < extract_syms.data + extract_syms.size;
			     esymp++) {
				if (sym_ptr == *esymp) {
					rm_reloc = true;
					break;
				}
			}
		}

		if (mode("keep"))
			rm_reloc = true;

		if (mode("keep-new-code")) {
			if (bfd_is_const_section(sym_ptr->section)) {
				rm_reloc = false;
			} else {
				bfd_vma offset = reloc_target_offset(ss, *relocp);
				struct span *target_span =
				    reloc_target_span(ss, *relocp);
				if (target_span->new ||
				    (target_span->ss->type == SS_TYPE_TEXT &&
				     sym_ptr->value + offset !=
				     target_span->start))
					rm_reloc = false;
			}

			const struct table_section *ts =
			    get_table_section(ss->name);
			if (ts != NULL && ts->has_addr &&
			    ((*relocp)->address % ts->entry_size ==
			     ts->addr_offset ||
			     (*relocp)->address % ts->entry_size ==
			     ts->other_offset))
				rm_reloc = false;
		}

		if (mode("finalize") && bfd_is_und_section(sym_ptr->section))
			rm_reloc = true;

		if (strcmp(sym_ptr->name, "mcount") == 0 &&
		    bfd_is_und_section(sym_ptr->section))
			rm_reloc = false;

		if (!find_span(ss, (*relocp)->address)->keep)
			rm_reloc = false;

		if (rm_reloc)
			write_ksplice_reloc(ss, *relocp);
		else
			*vec_grow(&ss->relocs, 1) = *relocp;
	}
}

struct supersect *make_section(struct superbfd *sbfd, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *name = vstrprintf(fmt, ap);
	va_end(ap);

	asection *sect = bfd_get_section_by_name(sbfd->abfd, name);
	if (sect != NULL)
		return fetch_supersect(sbfd, sect);
	else
		return new_supersect(sbfd, name);
}

arelent *create_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		      bfd_vma offset)
{
	bfd_reloc_code_real_type code;
	switch (bfd_arch_bits_per_address(ss->parent->abfd)) {
	case 32:
		code = BFD_RELOC_32;
		break;
	case 64:
		code = BFD_RELOC_64;
		break;
	default:
		DIE;
	}

	arelent *reloc = malloc(sizeof(*reloc));
	reloc->sym_ptr_ptr = symp;
	reloc->address = addr_offset(ss, addr);
	reloc->howto = bfd_reloc_type_lookup(ss->parent->abfd, code);
	reloc->addend = offset;
	return reloc;
}

void write_reloc(struct supersect *ss, const void *addr, asymbol **symp,
		 bfd_vma offset)
{
	*vec_grow(&ss->new_relocs, 1) = create_reloc(ss, addr, symp, offset);
}

void write_string(struct supersect *ss, const char **addr, const char *fmt, ...)
{
	va_list ap;
	struct supersect *str_ss = make_section(ss->parent, ".ksplice_str");
	char *str;
	va_start(ap, fmt);
	int len = vasprintf(&str, fmt, ap);
	assert(len >= 0);
	va_end(ap);

	unsigned long *str_offp = ulong_hash_lookup(&ksplice_string_offset, str,
						    FALSE);
	if (str_offp == NULL) {
		char *buf = sect_grow(str_ss, len + 1, char);
		memcpy(buf, str, len + 1);
		str_offp = ulong_hash_lookup(&ksplice_string_offset, str, TRUE);
		*str_offp = addr_offset(str_ss, buf);
	}

	write_reloc(ss, addr, &str_ss->symbol, *str_offp);
}

void lookup_system_map(struct addr_vec *addrs, const char *name, long offset)
{
	struct addr_vec *map_addrs =
	    addr_vec_hash_lookup(&system_map, name, FALSE);
	if (map_addrs == NULL)
		return;

	unsigned long *addr, *map_addr;
	for (map_addr = map_addrs->data;
	     map_addr < map_addrs->data + map_addrs->size; map_addr++) {
		for (addr = addrs->data; addr < addrs->data + addrs->size;
		     addr++) {
			if (*addr == *map_addr + offset)
				break;
		}
		if (addr < addrs->data + addrs->size)
			continue;
		*vec_grow(addrs, 1) = *map_addr + offset;
	}
}

void compute_system_map_array(struct superbfd *sbfd, struct addr_vec *addrs,
			      asymbol *sym)
{
	if (bfd_is_abs_section(sym->section)) {
		*vec_grow(addrs, 1) = sym->value;
	} else if (bfd_is_und_section(sym->section)) {
		lookup_system_map(addrs, sym->name, 0);
	} else if (!bfd_is_const_section(sym->section)) {
		asymbol **gsymp;
		for (gsymp = sbfd->syms.data;
		     gsymp < sbfd->syms.data + sbfd->syms.size; gsymp++) {
			asymbol *gsym = *gsymp;
			if ((gsym->flags & BSF_DEBUGGING) == 0 &&
			    gsym->section == sym->section)
				lookup_system_map(addrs, gsym->name,
						  sym->value - gsym->value);
		}
	}
}

void write_ksplice_system_map(struct superbfd *sbfd, asymbol *sym,
			      const char *label)
{
	bool *done = bool_hash_lookup(&system_map_written, label, TRUE);
	if (*done)
		return;
	*done = true;

	struct addr_vec addrs;
	vec_init(&addrs);

	compute_system_map_array(sbfd, &addrs, sym);
	if (addrs.size != 0) {
		struct supersect *smap_ss =
		    make_section(sbfd, ".ksplice_system_map");
		struct ksplice_system_map *smap =
		    sect_grow(smap_ss, 1, struct ksplice_system_map);
		write_string(smap_ss, &smap->label, "%s", label);

		struct supersect *array_ss = make_section(sbfd,
							  ".ksplice_array");
		void *buf = sect_grow(array_ss, addrs.size,
				      typeof(*addrs.data));
		memcpy(buf, addrs.data, addrs.size * sizeof(*addrs.data));
		smap->nr_candidates = addrs.size;
		write_reloc(smap_ss, &smap->candidates, &array_ss->symbol,
			    addr_offset(array_ss, buf));
	}
	vec_free(&addrs);
}

void write_ksplice_symbol_backend(struct supersect *ss,
				  struct ksplice_symbol *const *addr,
				  asymbol *sym, const char *label,
				  const char *name)
{
	struct supersect *ksymbol_ss = make_section(ss->parent,
						    ".ksplice_symbols");
	struct ksplice_symbol *ksymbol;
	unsigned long *ksymbol_offp;

	ksymbol_offp = ulong_hash_lookup(&ksplice_symbol_offset, label, FALSE);
	if (ksymbol_offp != NULL) {
		write_reloc(ss, addr, &ksymbol_ss->symbol, *ksymbol_offp);
		return;
	}
	ksymbol = sect_grow(ksymbol_ss, 1, struct ksplice_symbol);
	ksymbol_offp = ulong_hash_lookup(&ksplice_symbol_offset, label, TRUE);
	*ksymbol_offp = addr_offset(ksymbol_ss, ksymbol);

	write_reloc(ss, addr, &ksymbol_ss->symbol, *ksymbol_offp);
	write_string(ksymbol_ss, &ksymbol->label, "%s", label);
	if (name != NULL) {
		write_string(ksymbol_ss, &ksymbol->name, "%s", name);
		write_ksplice_system_map(ksymbol_ss->parent, sym, label);
	}
}

void write_ksplice_symbol(struct supersect *ss,
			  struct ksplice_symbol *const *addr,
			  asymbol *sym, struct span *span,
			  const char *addstr_sect)
{
	const char *label, *name;
	if (span != NULL && span->start != 0)
		label = span->label;
	else
		label = label_lookup(ss->parent, sym);

	asymbol *gsym = canonical_symbol(ss->parent, sym);
	if (strcmp(addstr_sect, "") != 0)
		name = NULL;
	else if (bfd_is_und_section(sym->section))
		name = sym->name;
	else if (bfd_is_const_section(sym->section))
		name = NULL;
	else if (span != NULL && span->symbol == NULL)
		name = NULL;
	else if (gsym == NULL || (gsym->flags & BSF_SECTION_SYM) != 0)
		name = NULL;
	else
		name = gsym->name;

	write_ksplice_symbol_backend(ss, addr, sym,
				     strprintf("%s%s", addstr_sect, label),
				     name);
}

void write_ksplice_reloc(struct supersect *ss, arelent *orig_reloc)
{
	asymbol *sym_ptr = *orig_reloc->sym_ptr_ptr;
	bfd_vma reloc_addend = reloc_offset(ss, orig_reloc);
	bfd_vma target_addend = reloc_target_offset(ss, orig_reloc);
	unsigned long *repladdr = ss->contents.data + orig_reloc->address;

	if (mode("finalize") && strstarts(ss->name, ".ksplice_patches")) {
		*repladdr = 0;
		return;
	}
	if (mode("finalize") && strstarts(ss->name, ".ksplice_relocs")) {
		assert(strstarts(sym_ptr->name, KSPLICE_SYMBOL_STR));
		asymbol fake_sym;
		fake_sym.name = sym_ptr->name + strlen(KSPLICE_SYMBOL_STR);
		fake_sym.section = bfd_und_section_ptr;
		fake_sym.value = 0;
		fake_sym.flags = 0;

		write_ksplice_symbol_backend
		    (ss, (struct ksplice_symbol **)repladdr, &fake_sym,
		     fake_sym.name, fake_sym.name);
		return;
	}

	struct span *span = reloc_target_span(ss, orig_reloc);
	if (span == ss->spans.data && span->start != target_addend)
		span = NULL;
	write_canary(ss, orig_reloc->address,
		     bfd_get_reloc_size(orig_reloc->howto),
		     orig_reloc->howto->dst_mask);

	struct supersect *kreloc_ss =
	    make_section(ss->parent, ".ksplice_relocs%s", ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	struct span *address_span = find_span(ss, orig_reloc->address);
	write_reloc(kreloc_ss, &kreloc->blank_addr,
		    &ss->symbol, orig_reloc->address + address_span->shift);
	if (bfd_is_und_section(sym_ptr->section) && mode("keep")) {
		char *name = strprintf(KSPLICE_SYMBOL_STR "%s", sym_ptr->name);
		asymbol **symp = make_undefined_symbolp(ss->parent, name);
		write_reloc(kreloc_ss, &kreloc->symbol, symp, 0);
	} else {
		write_ksplice_symbol(kreloc_ss, &kreloc->symbol, sym_ptr, span,
				     "");
	}
	if (span != NULL && span->start != 0) {
		reloc_addend += sym_ptr->value - span->start;
		target_addend += sym_ptr->value - span->start;
	}
	kreloc->insn_addend = reloc_addend - target_addend;
	kreloc->target_addend = target_addend;
	write_ksplice_reloc_howto(kreloc_ss, &kreloc->howto, orig_reloc->howto,
				  KSPLICE_HOWTO_RELOC);
}

static void write_ksplice_reloc_howto(struct supersect *ss, const
				      struct ksplice_reloc_howto *const *addr,
				      reloc_howto_type *howto,
				      enum ksplice_reloc_howto_type type)
{
	struct supersect *khowto_ss = make_section(ss->parent,
						   ".ksplice_reloc_howtos");
	struct ksplice_reloc_howto *khowto;
	unsigned long *khowto_offp;

	khowto_offp = ulong_hash_lookup(&ksplice_howto_offset, howto->name,
					FALSE);
	if (khowto_offp != NULL) {
		write_reloc(ss, addr, &khowto_ss->symbol, *khowto_offp);
		return;
	}
	khowto = sect_grow(khowto_ss, 1, struct ksplice_reloc_howto);
	khowto_offp = ulong_hash_lookup(&ksplice_howto_offset, howto->name,
					TRUE);
	*khowto_offp = addr_offset(khowto_ss, khowto);

	khowto->type = type;
	khowto->pcrel = howto->pc_relative;
	khowto->size = bfd_get_reloc_size(howto);
	khowto->dst_mask = howto->dst_mask;
	khowto->rightshift = howto->rightshift;
	khowto->signed_addend =
	    (howto->complain_on_overflow == complain_overflow_signed) ||
	    (howto->complain_on_overflow == complain_overflow_bitfield);
	write_reloc(ss, addr, &khowto_ss->symbol, *khowto_offp);
}

#define CANARY(x, canary) ((x & ~howto->dst_mask) | (canary & howto->dst_mask))

void write_canary(struct supersect *ss, int offset, bfd_size_type size,
		  bfd_vma dst_mask)
{
	int bits = size * 8;
	void *address = ss->contents.data + offset;
	bfd_vma x = bfd_get(bits, ss->parent->abfd, address);
	x = (x & ~dst_mask) | ((bfd_vma)KSPLICE_CANARY & dst_mask);
	bfd_put(bits, ss->parent->abfd, x, address);
}

static void write_date_relocs(struct superbfd *sbfd, const char *str,
			      enum ksplice_reloc_howto_type type)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type != SS_TYPE_STRING && ss->type != SS_TYPE_RODATA)
			continue;
		void *ptr;
		struct span *span;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (!span->keep)
				continue;
			for (ptr = ss->contents.data + span->start;
			     ptr + strlen(str) < ss->contents.data +
			     span->start + span->contents_size; ptr++) {
				if (strcmp((const char *)ptr, str) == 0)
					write_ksplice_date_reloc
					    (ss, addr_offset(ss, ptr), str,
					     type);
			}
		}
	}
}

static void write_ksplice_date_reloc(struct supersect *ss, unsigned long offset,
				     const char *str,
				     enum ksplice_reloc_howto_type type)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	const char *filename = ss->parent->abfd->filename;
	char *c = strstr(filename, ".KSPLICE");
	int flen = (c == NULL ? strlen(filename) : c - filename);

	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, NULL,
				     strprintf("%s<%.*s>", str, flen, filename),
				     NULL);

	struct span *span = find_span(ss, offset);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    offset + span->shift);
	write_ksplice_nonreloc_howto(kreloc_ss, &kreloc->howto, type,
				     strlen(str));
}

static void write_table_relocs(struct superbfd *sbfd, const char *sectname,
			       enum ksplice_reloc_howto_type type)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd, sectname);
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);

	const struct table_section *s = get_table_section(sectname);
	if (s == NULL)
		DIE;

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += s->entry_size) {
		struct span *span = find_span(ss, addr_offset(ss, entry));
		assert(span != NULL);
		if (!span->keep)
			continue;

		arelent *reloc = find_reloc(ss, entry + s->addr_offset);
		assert(reloc != NULL);
		asymbol *sym = *reloc->sym_ptr_ptr;
		assert(!bfd_is_const_section(sym->section));
		struct supersect *sym_ss = fetch_supersect(sbfd, sym->section);
		unsigned long addr = sym->value +
		    reloc_target_offset(ss, reloc);
		write_ksplice_table_reloc(sym_ss, addr, span->label, type);
	}
}

static void write_ksplice_table_reloc(struct supersect *ss,
				      unsigned long address,
				      const char *label,
				      enum ksplice_reloc_howto_type type)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", ss->name);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);
	struct span *span = find_span(ss, address);
	assert(span != NULL);

	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, NULL,
				     label, NULL);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    address + span->shift);
	write_ksplice_nonreloc_howto(kreloc_ss, &kreloc->howto, type, 0);
}

static void write_ksplice_nonreloc_howto(struct supersect *ss,
					 const struct ksplice_reloc_howto
					 *const *addr,
					 enum ksplice_reloc_howto_type type,
					 int size)
{
	struct supersect *khowto_ss =
	    make_section(ss->parent, ".ksplice_reloc_howtos");
	struct ksplice_reloc_howto *khowto =
	    sect_grow(khowto_ss, 1, struct ksplice_reloc_howto);

	khowto->type = type;
	khowto->size = size;
	khowto->pcrel = 0;
	khowto->dst_mask = 0;
	khowto->rightshift = 0;
	khowto->signed_addend = 0;
	write_reloc(ss, addr, &khowto_ss->symbol,
		    addr_offset(khowto_ss, khowto));
}

static void write_ksplice_symbol_reloc(struct supersect *ss,
				       const char *sectname,
				       unsigned long *addr, asymbol *sym,
				       const char *label, const char *name)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", sectname);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, sym, label,
				     name);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    addr_offset(ss, addr));
	write_ksplice_nonreloc_howto(kreloc_ss, &kreloc->howto,
				     KSPLICE_HOWTO_SYMBOL, 0);
}

static void write_ksplice_section(struct span *span)
{
	struct supersect *ss = span->ss;
	const char *sectname = span->ss->name;
	const struct table_section *ts = get_table_section(ss->name);

	if (ts != NULL && ts->has_addr) {
		arelent *reloc = find_reloc(ss, ss->contents.data + span->start
					    + ts->addr_offset);
		assert(reloc != NULL);
		asymbol *rsym = *reloc->sym_ptr_ptr;
		assert(!bfd_is_const_section(rsym->section));
		sectname = rsym->section->name;
	}

	struct supersect *ksect_ss =
	    make_section(ss->parent, ".ksplice_sections%s", sectname);
	struct ksplice_section *ksect = sect_grow(ksect_ss, 1,
						  struct ksplice_section);
	asymbol *sym = span->symbol == NULL ? ss->symbol : span->symbol;

	write_ksplice_symbol(ksect_ss, &ksect->symbol, sym, span,
			     mode("keep-new-code") ? "(post)" : "");
	ksect->size = span->size;
	ksect->flags = 0;

	if (ss->type == SS_TYPE_RODATA || ss->type == SS_TYPE_STRING ||
	    ss->type == SS_TYPE_EXPORT || ss->type == SS_TYPE_BUGTABLE)
		ksect->flags |= KSPLICE_SECTION_RODATA;
	if (ss->type == SS_TYPE_DATA)
		ksect->flags |= KSPLICE_SECTION_DATA;
	if (ss->type == SS_TYPE_TEXT)
		ksect->flags |= KSPLICE_SECTION_TEXT;
	assert(ksect->flags != 0);

	if (ss->type == SS_TYPE_STRING)
		ksect->flags |= KSPLICE_SECTION_STRING;
	if (ss->match_data_early)
		ksect->flags |= KSPLICE_SECTION_MATCH_DATA_EARLY;

	write_reloc(ksect_ss, &ksect->address, &ss->symbol,
		    span->start + span->shift);

	if (mode("keep-old-code")) {
		/* Write ksplice_symbols for all the entry points */
		struct entry_point *entry;
		for (entry = span->entry_points.data;
		     entry < span->entry_points.data + span->entry_points.size;
		     entry++)
			write_ksplice_symbol_reloc
			    (span->ss, sectname, span->ss->contents.data +
			     span->start + span->shift + entry->offset,
			     entry->symbol, entry->label, entry->name);
	}
}

static void write_ksplice_patch_reloc(struct supersect *ss,
				      const char *sectname, unsigned long *addr,
				      bfd_size_type size, const char *label,
				      long addend)
{
	struct supersect *kreloc_ss;
	kreloc_ss = make_section(ss->parent, ".ksplice_relocs%s", sectname);
	struct ksplice_reloc *kreloc = sect_grow(kreloc_ss, 1,
						 struct ksplice_reloc);

	write_canary(ss, addr_offset(ss, addr), size, -1);
	write_ksplice_symbol_backend(kreloc_ss, &kreloc->symbol, NULL,
				     label, NULL);
	write_reloc(kreloc_ss, &kreloc->blank_addr, &ss->symbol,
		    addr_offset(ss, addr));
	reloc_howto_type *howto =
	    bfd_reloc_type_lookup(ss->parent->abfd,
				  PASTE(BFD_RELOC_, LONG_BIT));
	write_ksplice_reloc_howto(kreloc_ss, &kreloc->howto, howto,
				  KSPLICE_HOWTO_RELOC);
	kreloc->target_addend = addend;
	kreloc->insn_addend = 0;
}

/* Assumes symbol is global, aka only one symbol of that name */
static asymbol *name_to_symbol(struct superbfd *sbfd, const char *name)
{
	if (name == NULL)
		return NULL;

	asymbol **symp;
	for (symp = sbfd->syms.data;
	     symp < sbfd->syms.data + sbfd->syms.size; symp++) {
		asymbol *sym = *symp;
		if (strcmp(name, sym->name) == 0 &&
		    ((sym->flags & BSF_GLOBAL) != 0 ||
		     bfd_is_und_section(sym->section)))
			return sym;
	}
	return NULL;
}

void write_ksplice_patches(struct superbfd *sbfd, struct span *span)
{
	if (span->datapatch) {
		write_ksplice_patch(sbfd, span, span->label, 0);
		return;
	}

	assert(span->patch);

	long prev_offset = LONG_MIN;
	asymbol *prev_sym = NULL;
	const char *prev_label = NULL;
	struct entry_point *entry;
	for (entry = span->pre_entry_points.data;
	     entry < span->pre_entry_points.data + span->pre_entry_points.size;
	     entry++) {
		asymbol *sym = name_to_symbol(sbfd, entry->name);
		if (sym == NULL && entry->offset != 0) {
			/* Since it was global, name and label are the same */
			write_ksplice_deleted_patch
			    (sbfd, entry->label, entry->label, span->ss->name,
			     entry->offset);
		} else if (entry->offset != prev_offset) {
			debug1(sbfd, "entry point: %s(%s) %lx\n", entry->label,
			       entry->name, entry->offset);

			if (prev_offset + MAX_TRAMPOLINE_SIZE > entry->offset) {
				err(sbfd,
				    "Overlapping trampolines: %s %lx/%lx\n",
				    span->label, prev_offset, entry->offset);
				DIE;
			}

			long target_offset = 0;
			if (sym != NULL)
				target_offset = sym->value - span->start;
			write_ksplice_patch(sbfd, span, entry->label,
					    target_offset);
			prev_offset = entry->offset;
			prev_sym = NULL;
		}

		if (prev_sym == NULL) {
			prev_sym = sym;
			prev_label = entry->label;
		} else if (sym != NULL &&
			   (prev_sym->section != sym->section ||
			    prev_sym->value != sym->value)) {
			err(sbfd, "Splitting global symbols in the middle of a "
			    "span: %s+%lx != %s+%lx!\n",
			    prev_label, (unsigned long)prev_sym->value,
			    entry->label, (unsigned long)sym->value);
			DIE;
		}
	}

	if (prev_offset + MAX_TRAMPOLINE_SIZE > span->size) {
		err(sbfd, "Trampoline ends outside span: %s %lx/%lx\n",
		    span->label, prev_offset, (unsigned long)span->size);
		DIE;
	}
}

void write_ksplice_patch(struct superbfd *sbfd, struct span *span,
			 const char *label, long offset)
{
	struct supersect *kpatch_ss =
	    make_section(sbfd, ".ksplice_patches%s", span->ss->name);
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);

	write_ksplice_patch_reloc(kpatch_ss, span->ss->name, &kpatch->oldaddr,
				  sizeof(kpatch->oldaddr), label, 0);
	if (span->ss->type == SS_TYPE_TEXT) {
		kpatch->type = KSPLICE_PATCH_TEXT;
		write_patch_storage(kpatch_ss, kpatch, MAX_TRAMPOLINE_SIZE,
				    NULL);
	} else {
		kpatch->type = KSPLICE_PATCH_DATA;
		kpatch->size = span->contents_size;
		struct supersect *data_ss =
		    make_section(sbfd, ".ksplice_patch_data");
		write_reloc(kpatch_ss, &kpatch->contents, &span->ss->symbol,
			    span->start + span->shift);
		char *saved = sect_do_grow(data_ss, 1, span->contents_size, 1);
		write_reloc(kpatch_ss, &kpatch->saved, &data_ss->symbol,
			    addr_offset(data_ss, saved));
	}
	write_reloc(kpatch_ss, &kpatch->repladdr, &span->ss->symbol,
		    span->start + span->shift + offset);
}

asymbol **make_undefined_symbolp(struct superbfd *sbfd, const char *name)
{
	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if (strcmp(name, sym->name) == 0 &&
		    bfd_is_und_section(sym->section))
			return symp;
	}
	asymbol ***sympp;
	for (sympp = sbfd->new_syms.data;
	     sympp < sbfd->new_syms.data + sbfd->new_syms.size; sympp++) {
		asymbol **symp = *sympp;
		asymbol *sym = *symp;
		if (strcmp(name, sym->name) == 0 &&
		    bfd_is_und_section(sym->section))
			return symp;
	}

	symp = malloc(sizeof(*symp));
	*symp = bfd_make_empty_symbol(sbfd->abfd);
	asymbol *sym = *symp;
	sym->name = name;
	sym->section = bfd_und_section_ptr;
	sym->flags = 0;
	sym->value = 0;
	*vec_grow(&sbfd->new_syms, 1) = symp;
	return symp;
}

void write_ksplice_deleted_patch(struct superbfd *sbfd, const char *name,
				 const char *label, const char *sectname,
				 long offset)
{
	struct supersect *kpatch_ss =
	    make_section(sbfd, ".ksplice_patches%s", sectname);
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);

	write_ksplice_patch_reloc(kpatch_ss, sectname, &kpatch->oldaddr,
				  sizeof(kpatch->oldaddr), label, 0);
	kpatch->type = KSPLICE_PATCH_TEXT;
	asymbol **symp = make_undefined_symbolp(sbfd, strdup(name));
	write_reloc(kpatch_ss, &kpatch->repladdr, symp, offset);
	write_patch_storage(kpatch_ss, kpatch, MAX_TRAMPOLINE_SIZE, NULL);
}

void write_ksplice_export(struct superbfd *sbfd, struct span *span, bool del)
{
	struct supersect *kpatch_ss = make_section(sbfd, ".ksplice_patches");
	struct ksplice_patch *kpatch = sect_grow(kpatch_ss, 1,
						 struct ksplice_patch);
	struct supersect *data_ss;

	const struct table_section *ts = get_table_section(span->ss->name);
	assert(ts != NULL);
	const char **addr =
	    span->ss->contents.data + span->start + ts->other_offset;
	const char *symname = read_string(span->ss, addr);

	char *oldname, *newname;
	if (del) {
		oldname = strprintf("%s:%s", span->ss->name, symname);
		newname = strprintf("DISABLED_%s_%s", symname, kid);
	} else {
		oldname = strprintf("%s:DISABLED_%s_%s", span->ss->name,
				    symname, kid);
		newname = strprintf("%s", symname);
		write_string(span->ss, addr, "DISABLED_%s_%s", symname, kid);
	}

	write_ksplice_patch_reloc(kpatch_ss, "", &kpatch->oldaddr,
				  sizeof(kpatch->oldaddr), oldname,
				  ts->other_offset);
	kpatch->type = KSPLICE_PATCH_EXPORT;
	const char **namep = write_patch_storage(kpatch_ss, kpatch,
						 sizeof(newname), &data_ss);
	write_string(data_ss, namep, "%s", newname);
}

void filter_table_sections(struct superbfd *isbfd)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		struct table_section s = *ts;
		s.sect = read_string(tables_ss, &ts->sect);
		s.other_sect = read_string(tables_ss, &ts->other_sect);
		s.crc_sect = read_string(tables_ss, &ts->crc_sect);
		filter_table_section(isbfd, &s);
	}
}

void filter_table_section(struct superbfd *sbfd, const struct table_section *s)
{
	asection *isection = bfd_get_section_by_name(sbfd->abfd, s->sect);
	if (isection == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, isection);

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += s->entry_size) {
		struct span *span = find_span(ss, addr_offset(ss, entry));
		assert(span != NULL);

		if (s->has_addr) {
			struct span *sym_span =
			    span_offset_target_span(span, s->addr_offset);
			assert(sym_span != NULL);
			if (sym_span->keep)
				keep_span(span);
		}

		if (s->other_sect != NULL) {
			struct span *sym_span =
			    span_offset_target_span(span, s->other_offset);
			assert(sym_span != NULL);
			if (span->keep)
				keep_span(sym_span);
		}

		if (s->crc_sect != NULL) {
			struct span *crc_span = get_crc_span(span, s);
			assert(crc_span != NULL);
			if (span->keep && mode("keep-new-code"))
				keep_span(crc_span);
		}
	}
}

static void match_other_spans(struct span *old_span, struct span *new_span)
{
	const struct table_section *ts = get_table_section(old_span->ss->name);
	if (ts == NULL)
		return;

	if (old_span->match == new_span && new_span->match == old_span &&
	    ts->other_sect != NULL) {
		void *old_entry = old_span->ss->contents.data + old_span->start;
		void *new_entry = new_span->ss->contents.data + new_span->start;
		arelent *old_reloc =
		    find_reloc(old_span->ss, old_entry + ts->other_offset);
		arelent *new_reloc =
		    find_reloc(new_span->ss, new_entry + ts->other_offset);
		assert(old_reloc != NULL && new_reloc != NULL);
		struct span *old_other_span =
		    reloc_target_span(old_span->ss, old_reloc);
		struct span *new_other_span =
		    reloc_target_span(new_span->ss, new_reloc);
		assert(old_other_span != NULL && new_other_span != NULL);
		match_spans(old_other_span, new_other_span);
	}
}

static void match_table_spans(struct span *old_span, struct span *new_span)
{
	const struct table_section *ts = get_table_section(old_span->ss->name);

	if (strcmp(old_span->ss->name, new_span->ss->name) != 0)
		return;
	if (ts == NULL || old_span->ss->type != SS_TYPE_SPECIAL ||
	    new_span->ss->type != SS_TYPE_SPECIAL)
		return;
	if (old_span->match != NULL || new_span->match != NULL)
		return;

	if (ts->has_addr) {
		void *old_entry = old_span->ss->contents.data + old_span->start;
		void *new_entry = new_span->ss->contents.data + new_span->start;
		arelent *old_reloc =
		    find_reloc(old_span->ss, old_entry + ts->addr_offset);
		arelent *new_reloc =
		    find_reloc(new_span->ss, new_entry + ts->addr_offset);
		assert(old_reloc != NULL && new_reloc != NULL);
		struct span *old_sym_span =
		    reloc_target_span(old_span->ss, old_reloc);
		struct span *new_sym_span =
		    reloc_target_span(new_span->ss, new_reloc);
		assert(old_sym_span != NULL && new_sym_span != NULL);
		if (old_sym_span->match == new_sym_span &&
		    new_sym_span->match == old_sym_span &&
		    old_reloc->address - old_sym_span->start ==
		    new_reloc->address - new_sym_span->start)
			match_spans(old_span, new_span);
	}
}

static struct span *get_crc_span(struct span *span,
				 const struct table_section *ts)
{
	void *entry = span->ss->contents.data + span->start;
	asection *crc_sect = bfd_get_section_by_name(span->ss->parent->abfd,
						     ts->crc_sect);
	if (crc_sect == NULL)
		return NULL;
	struct supersect *crc_ss = fetch_supersect(span->ss->parent, crc_sect);
	if (crc_ss == NULL)
		return NULL;
	struct span *crc_span = find_span(crc_ss, addr_offset(span->ss, entry) /
					  ts->entry_size * ts->crc_size);
	return crc_span;
}

void mark_precallable_spans(struct superbfd *sbfd)
{
	asection *sect;
	struct supersect *ss, *sym_ss;
	struct span *address_span, *target_span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		ss = fetch_supersect(sbfd, sect);
		arelent **relocp;
		if (ss->type == SS_TYPE_SPECIAL)
			continue;
		for (relocp = ss->relocs.data;
		     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
			asymbol *sym = *(*relocp)->sym_ptr_ptr;
			address_span = find_span(ss, (*relocp)->address);
			if (!address_span->precallable)
				continue;
			target_span = reloc_target_span(ss, *relocp);
			if (target_span == NULL || target_span->keep)
				continue;
			sym_ss = fetch_supersect(sbfd, sym->section);
			if (sym_ss->type == SS_TYPE_IGNORED)
				continue;
			target_span->precallable = true;
			changed = true;
		}
	}
}

void keep_referenced_sections(struct superbfd *sbfd)
{
	asection *sect;
	struct supersect *ss, *sym_ss;
	struct span *address_span, *target_span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		ss = fetch_supersect(sbfd, sect);
		arelent **relocp;
		if (ss->type == SS_TYPE_SPECIAL)
			continue;
		for (relocp = ss->relocs.data;
		     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
			asymbol *sym = *(*relocp)->sym_ptr_ptr;
			address_span = find_span(ss, (*relocp)->address);
			if (!address_span->keep)
				continue;
			target_span = reloc_target_span(ss, *relocp);
			if (target_span == NULL || target_span->keep)
				continue;
			sym_ss = fetch_supersect(sbfd, sym->section);
			if (sym_ss->type == SS_TYPE_IGNORED)
				continue;
			keep_span(target_span);
			changed = true;
		}
	}
}

void copy_symbols(struct asymbolp_vec *osyms, struct asymbolpp_vec *isyms)
{
	asymbol ***sympp;
	for (sympp = isyms->data; sympp < isyms->data + isyms->size; sympp++)
		*vec_grow(osyms, 1) = **sympp;
}

/* Modified function from GNU Binutils objcopy.c */
bfd_boolean copy_object(bfd *ibfd, bfd *obfd)
{
	assert(bfd_set_format(obfd, bfd_get_format(ibfd)));

	bfd_vma start = bfd_get_start_address(ibfd);

	flagword flags = bfd_get_file_flags(ibfd);
	flags &= bfd_applicable_file_flags(obfd);

	assert(bfd_set_start_address(obfd, start)
	       && bfd_set_file_flags(obfd, flags));

	enum bfd_architecture iarch = bfd_get_arch(ibfd);
	unsigned int imach = bfd_get_mach(ibfd);
	assert(bfd_set_arch_mach(obfd, iarch, imach));
	assert(bfd_set_format(obfd, bfd_get_format(ibfd)));

	/* BFD mandates that all output sections be created and sizes set before
	   any output is done.  Thus, we traverse all sections multiple times.  */
	bfd_map_over_sections(ibfd, setup_section, obfd);

	struct supersect *new_supersects = fetch_superbfd(ibfd)->new_supersects;
	struct supersect *ss;
	for (ss = new_supersects; ss != NULL; ss = ss->next)
		setup_new_section(obfd, ss);

	/* Mark symbols used in output relocations so that they
	   are kept, even if they are local labels or static symbols.

	   Note we iterate over the input sections examining their
	   relocations since the relocations for the output sections
	   haven't been set yet.  mark_symbols_used_in_relocations will
	   ignore input sections which have no corresponding output
	   section.  */

	bfd_map_over_sections(ibfd, mark_symbols_used_in_relocations, NULL);
	for (ss = new_supersects; ss != NULL; ss = ss->next)
		ss_mark_symbols_used_in_relocations(ss);
	struct asymbolp_vec osyms;
	vec_init(&osyms);
	filter_symbols(ibfd, obfd, &osyms, &fetch_superbfd(ibfd)->syms);
	copy_symbols(&osyms, &fetch_superbfd(ibfd)->new_syms);

	bfd_set_symtab(obfd, osyms.data, osyms.size);

	/* This has to happen after the symbol table has been set.  */
	bfd_map_over_sections(obfd, write_section, NULL);

	/* Allow the BFD backend to copy any private data it understands
	   from the input BFD to the output BFD.  This is done last to
	   permit the routine to look at the filtered symbol table, which is
	   important for the ECOFF code at least.  */
	assert(bfd_copy_private_bfd_data(ibfd, obfd));

	return TRUE;
}

/* Modified function from GNU Binutils objcopy.c */
void setup_section(bfd *ibfd, asection *isection, void *obfdarg)
{
	struct superbfd *isbfd = fetch_superbfd(ibfd);
	struct supersect *ss = fetch_supersect(isbfd, isection);
	bfd *obfd = obfdarg;
	bfd_vma vma;

	if (!ss->keep)
		return;

	asection *osection = bfd_make_section_anyway(obfd, ss->name);
	assert(osection != NULL);

	osection->userdata = ss;
	bfd_set_section_flags(obfd, osection, ss->flags);
	ss->symbol = osection->symbol;
	assert(bfd_set_section_size(obfd, osection, ss->contents.size));

	vma = bfd_section_vma(ibfd, isection);
	assert(bfd_set_section_vma(obfd, osection, vma));

	osection->lma = isection->lma;
	assert(bfd_set_section_alignment(obfd, osection, ss->alignment));
	osection->entsize = ss->entsize;
	osection->output_section = osection;
	osection->output_offset = 0;
	isection->output_section = osection;
	isection->output_offset = 0;
	return;
}

void setup_new_section(bfd *obfd, struct supersect *ss)
{
	asection *osection = bfd_make_section_anyway(obfd, ss->name);
	assert(osection != NULL);
	bfd_set_section_flags(obfd, osection, ss->flags);

	osection->userdata = ss;
	ss->symbol = osection->symbol;
	assert(bfd_set_section_size(obfd, osection, ss->contents.size));
	assert(bfd_set_section_vma(obfd, osection, 0));

	osection->lma = 0;
	assert(bfd_set_section_alignment(obfd, osection, ss->alignment));
	osection->entsize = ss->entsize;
	osection->output_section = osection;
	osection->output_offset = 0;
}

static int compare_reloc_addresses(const void *aptr, const void *bptr)
{
	const arelent *const *a = aptr, *const *b = bptr;
	return (*a)->address - (*b)->address;
}

static void delete_obsolete_relocs(struct supersect *ss)
{
	if (ss->new_relocs.size == 0)
		return;

	qsort(ss->relocs.data, ss->relocs.size, sizeof(*ss->relocs.data),
	      compare_reloc_addresses);
	qsort(ss->new_relocs.data, ss->new_relocs.size,
	      sizeof(*ss->new_relocs.data), compare_reloc_addresses);

	struct arelentp_vec orig_relocs;
	vec_move(&orig_relocs, &ss->relocs);

	arelent **relocp, **new_relocp = ss->new_relocs.data;
	for (relocp = orig_relocs.data;
	     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
		while (new_relocp < ss->new_relocs.data + ss->new_relocs.size &&
		       (*new_relocp)->address < (*relocp)->address)
			new_relocp++;
		arelent *reloc = *relocp, *new_reloc = *new_relocp;
		if (new_relocp == ss->new_relocs.data + ss->new_relocs.size ||
		    reloc->address != new_reloc->address)
			*vec_grow(&ss->relocs, 1) = reloc;
	}
}

void write_section(bfd *obfd, asection *osection, void *arg)
{
	struct supersect *ss = osection->userdata;

	if ((ss->flags & SEC_GROUP) != 0 || ss->contents.size == 0)
		return;

	delete_obsolete_relocs(ss);

	arelent **relocp;
	char *error_message;
	for (relocp = ss->new_relocs.data;
	     relocp < ss->new_relocs.data + ss->new_relocs.size; relocp++) {
		bfd_vma val;
		if (bfd_get_arch(obfd) == bfd_arch_arm)
			val = osection->use_rela_p ? 0 : (*relocp)->addend;
		else
			val = 0;
		bfd_put(bfd_get_reloc_size((*relocp)->howto) * 8, obfd, val,
			ss->contents.data + (*relocp)->address);
		if (bfd_install_relocation(obfd, *relocp, ss->contents.data,
					   0, osection, &error_message) !=
		    bfd_reloc_ok) {
			err(ss->parent, "ksplice: error installing reloc: %s",
			    error_message);
			DIE;
		}
		if (mode("finalize")) {
			/* Check that all our sections will be allocated */
			asymbol *sym = *((*relocp)->sym_ptr_ptr);
			if (!bfd_is_const_section(sym->section)) {
				struct supersect *sym_ss =
				    fetch_supersect(ss->parent, sym->section);
				assert((sym_ss->flags & SEC_ALLOC) != 0);
			}
		}
	}
	memcpy(vec_grow(&ss->relocs, ss->new_relocs.size), ss->new_relocs.data,
	       ss->new_relocs.size * sizeof(*ss->new_relocs.data));

	bfd_set_reloc(obfd, osection,
		      ss->relocs.size == 0 ? NULL : ss->relocs.data,
		      ss->relocs.size);

	if (ss->flags & SEC_HAS_CONTENTS)
		assert(bfd_set_section_contents
		       (obfd, osection, ss->contents.data, 0,
			ss->contents.size));
}

/* Modified function from GNU Binutils objcopy.c
 *
 * Mark all the symbols which will be used in output relocations with
 * the BSF_KEEP flag so that those symbols will not be stripped.
 *
 * Ignore relocations which will not appear in the output file.
 */
void mark_symbols_used_in_relocations(bfd *abfd, asection *isection,
				      void *ignored)
{
	struct superbfd *sbfd = fetch_superbfd(abfd);
	if (isection->output_section == NULL)
		return;

	struct supersect *ss = fetch_supersect(sbfd, isection);
	ss_mark_symbols_used_in_relocations(ss);
}

void ss_mark_symbols_used_in_relocations(struct supersect *ss)
{
	/* Examine each symbol used in a relocation.  If it's not one of the
	   special bfd section symbols, then mark it with BSF_KEEP.  */
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (!(bfd_is_const_section(sym->section) &&
		      sym == sym->section->symbol))
			sym->flags |= BSF_KEEP;
	}
	for (relocp = ss->new_relocs.data;
	     relocp < ss->new_relocs.data + ss->new_relocs.size; relocp++) {
		asymbol *sym = *(*relocp)->sym_ptr_ptr;
		if (!(bfd_is_const_section(sym->section) &&
		      sym == sym->section->symbol))
			sym->flags |= BSF_KEEP;
	}
}

static bool deleted_table_section_symbol(bfd *abfd, asymbol *sym)
{
	struct superbfd *sbfd = fetch_superbfd(abfd);
	if (bfd_is_const_section(sym->section))
		return false;
	struct supersect *ss = fetch_supersect(sbfd, sym->section);

	asymbol **symp;
	for (symp = ss->syms.data; symp < ss->syms.data + ss->syms.size; symp++) {
		if (sym == *symp)
			break;
	}
	return symp >= ss->syms.data + ss->syms.size &&
	    (sym->flags & BSF_SECTION_SYM) == 0;
}

void filter_symbols(bfd *ibfd, bfd *obfd, struct asymbolp_vec *osyms,
		    struct asymbolp_vec *isyms)
{
	asymbol **symp;
	struct superbfd *sbfd = fetch_superbfd(ibfd);
	for (symp = isyms->data; symp < isyms->data + isyms->size; symp++) {
		asymbol *sym = *symp;
		struct supersect *sym_ss = NULL;
		struct span *sym_span = NULL;
		if (!bfd_is_const_section(sym->section)) {
			sym_ss = fetch_supersect(sbfd, sym->section);
			sym_span = find_span(sym_ss, sym->value);
		}

		if (mode("keep") && (sym->flags & BSF_GLOBAL) != 0 &&
		    !(mode("keep-new-code") && sym_span != NULL &&
		      sym_span->new))
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		if (mode("finalize") && (sym->flags & BSF_GLOBAL) != 0)
			sym->flags = (sym->flags & ~BSF_GLOBAL) | BSF_LOCAL;

		bool keep = bfd_is_const_section(sym->section) ||
		    (sym_ss->keep && (sym->flags & BSF_SECTION_SYM) != 0) ||
		    (sym_span != NULL && sym_span->keep);
		if (bfd_is_und_section(sym->section) &&
		    (sym->flags & BSF_KEEP) == 0)
			keep = false;
		if (bfd_is_abs_section(sym->section) &&
		    (sym->flags & BSF_KEEP) == 0 &&
		    (sym->flags & BSF_FILE) == 0)
			keep = false;
		if (deleted_table_section_symbol(ibfd, sym))
			keep = false;

		if (mode("keep-old-code") && sym_ss != NULL &&
		    sym_ss->type == SS_TYPE_EXPORT)
			keep = false;

		if (keep) {
			if (sym_ss != NULL && !sym_ss->keep) {
				err(sbfd, "Kept symbol %s in unkept section "
				    "%s\n", sym->name, sym->section->name);
				DIE;
			}
			*vec_grow(osyms, 1) = sym;
		}
	}
}

static bool is_table_section(const char *name, bool consider_other,
			     bool consider_crc)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		if (strcmp(name, read_string(tables_ss, &ts->sect)) == 0)
			return true;
		const char *osect_name = read_string(tables_ss,
						     &ts->other_sect);
		if (consider_other && osect_name != NULL &&
		    strcmp(name, osect_name) == 0)
			return true;
		const char *crc_name = read_string(tables_ss, &ts->crc_sect);
		if (consider_crc && crc_name != NULL &&
		    strcmp(name, crc_name) == 0)
			return true;
	}
	return false;
}

const struct table_section *get_table_section(const char *name)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		if (strcmp(name, read_string(tables_ss, &ts->sect)) == 0) {
			if (ts->entry_contents_size != 0)
				assert(align(ts->entry_contents_size,
					     ts->entry_align) ==
				       ts->entry_size);
			struct table_section *ns = malloc(sizeof(*ns));
			*ns = *ts;
			ns->sect = read_string(tables_ss, &ts->sect);
			ns->crc_sect = read_string(tables_ss, &ts->crc_sect);
			ns->other_sect =
			    read_string(tables_ss, &ts->other_sect);
			return ns;
		}
	}
	return NULL;
}

enum supersect_type supersect_type(struct supersect *ss)
{
	if (mode("finalize") &&
	    strcmp(finalize_target, "vmlinux") == 0 &&
	    (strstarts(ss->name, ".ksplice_relocs.exit") ||
	     strstarts(ss->name, ".ksplice_sections.exit") ||
	     strstarts(ss->name, ".ksplice_patches.exit")))
		return SS_TYPE_EXIT;
	if (strstarts(ss->name, ".ksplice_call"))
		return SS_TYPE_KSPLICE_CALL;
	if (strstarts(ss->name, ".ksplice_extract"))
		return SS_TYPE_KSPLICE_EXTRACT;
	if (strstarts(ss->name, ".ksplice_options"))
		return SS_TYPE_SPECIAL;
	if (strstarts(ss->name, ".ksplice"))
		return SS_TYPE_KSPLICE;

	if (strstarts(ss->name, ".init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".security_initcall.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".con_initcall.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".x86cpuvendor.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".early_param.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".taglist.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".x86_cpu_dev.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".arch.info.init"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".proc.info.init"))
		return SS_TYPE_IGNORED;
	/* .pci_fixup_* sections really should be treated as global rodata
	   referenced only from quirks.c */
	if (strstarts(ss->name, ".pci_fixup_"))
		return SS_TYPE_IGNORED;
	/* .builtin_fw sections are similar to .pci_fixup */
	if (strstarts(ss->name, ".builtin_fw"))
		return SS_TYPE_IGNORED;
	/* same for .tracedata */
	if (strstarts(ss->name, ".tracedata"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".debug"))
		return SS_TYPE_IGNORED;
	/* .eh_frame should probably be discarded, not ignored */
	if (strstarts(ss->name, ".eh_frame"))
		return SS_TYPE_IGNORED;
	if (config->ignore_devinit && strstarts(ss->name, ".devinit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_meminit && strstarts(ss->name, ".meminit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_cpuinit && strstarts(ss->name, ".cpuinit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_devinit && strstarts(ss->name, ".devexit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_meminit && strstarts(ss->name, ".memexit"))
		return SS_TYPE_IGNORED;
	if (config->ignore_cpuinit && strstarts(ss->name, ".cpuexit"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".vgetcpu_mode") ||
	    strstarts(ss->name, ".jiffies") ||
	    strstarts(ss->name, ".wall_jiffies") ||
	    strstarts(ss->name, ".vxtime") ||
	    strstarts(ss->name, ".sys_tz") ||
	    strstarts(ss->name, ".sysctl_vsyscall") ||
	    strstarts(ss->name, ".xtime") ||
	    strstarts(ss->name, ".xtime_lock") ||
	    strstarts(ss->name, ".vsyscall"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".vdso"))
		return SS_TYPE_IGNORED;

	if (strstarts(ss->name, ".exit.text"))
		return SS_TYPE_TEXT;
	if (strstarts(ss->name, ".exit.data"))
		return SS_TYPE_DATA;

	if (strstarts(ss->name, ".text") ||
	    strstarts(ss->name, ".kernel.text") ||
	    strstarts(ss->name, ".devinit.text") ||
	    strstarts(ss->name, ".meminit.text") ||
	    strstarts(ss->name, ".cpuinit.text") ||
	    strstarts(ss->name, ".devexit.text") ||
	    strstarts(ss->name, ".memexit.text") ||
	    strstarts(ss->name, ".cpuexit.text") ||
	    strstarts(ss->name, ".ref.text") ||
	    strstarts(ss->name, ".spinlock.text") ||
	    strstarts(ss->name, ".kprobes.text") ||
	    strstarts(ss->name, ".sched.text") ||
	    strstarts(ss->name, ".entry.text") ||	/* OpenVZ */
	    (mode("keep-old-code") && strstarts(ss->name, ".fixup")))
		return SS_TYPE_TEXT;

	int n = -1;
	if (sscanf(ss->name, ".rodata.str%*u.%*u%n", &n) >= 0 &&
	    n == strlen(ss->name))
		return ss->entsize == 1 ? SS_TYPE_STRING : SS_TYPE_RODATA;

	if (strstarts(ss->name, ".rodata") ||
	    strstarts(ss->name, ".kernel.rodata") ||
	    strstarts(ss->name, ".devinit.rodata") ||
	    strstarts(ss->name, ".meminit.rodata") ||
	    strstarts(ss->name, ".cpuinit.rodata") ||
	    strstarts(ss->name, ".devexit.rodata") ||
	    strstarts(ss->name, ".memexit.rodata") ||
	    strstarts(ss->name, ".cpuexit.rodata") ||
	    strstarts(ss->name, ".ref.rodata") ||
	    strstarts(ss->name, "__tracepoints_strings") ||
	    strstarts(ss->name, "__markers_strings") ||
	    (mode("keep-old-code") && strstarts(ss->name, "__ex_table")))
		return SS_TYPE_RODATA;

	if (strstarts(ss->name, ".bss"))
		return SS_TYPE_DATA;

	/* Ignore .data.percpu sections */
	if (strstarts(ss->name, ".data.percpu") ||
	    strstarts(ss->name, ".kernel.data.percpu") ||
	    strstarts(ss->name, ".data..percpu"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".data") ||
	    strstarts(ss->name, ".kernel.data") ||
	    strstarts(ss->name, ".devinit.data") ||
	    strstarts(ss->name, ".cpuinit.data") ||
	    strstarts(ss->name, ".meminit.data") ||
	    strstarts(ss->name, ".devexit.data") ||
	    strstarts(ss->name, ".memexit.data") ||
	    strstarts(ss->name, ".cpuexit.data") ||
	    strstarts(ss->name, ".ref.data") ||
	    strstarts(ss->name, "__tracepoints") ||
	    strstarts(ss->name, "__markers"))
		return SS_TYPE_DATA;

	/* We replace all the ksymtab strings, so delete them */
	if (strcmp(ss->name, "__ksymtab_strings") == 0)
		return SS_TYPE_STRING;
	if (strstarts(ss->name, "__ksymtab"))
		return SS_TYPE_EXPORT;

	if (strstarts(ss->name, "__bug_table"))
		return SS_TYPE_BUGTABLE;

	if (is_table_section(ss->name, true, true))
		return SS_TYPE_SPECIAL;

	if (strstarts(ss->name, ".ARM."))
		return SS_TYPE_SPECIAL;

	if (strstarts(ss->name, ".note"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".comment"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, "__param"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, "__obsparm"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".exitcall.exit"))
		return SS_TYPE_IGNORED;
	if (strstarts(ss->name, ".modinfo"))
		return SS_TYPE_IGNORED;

	return SS_TYPE_UNKNOWN;
}

void initialize_supersect_types(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		ss->type = supersect_type(ss);
		ss->orig_type = ss->type;
		if (ss->type == SS_TYPE_UNKNOWN) {
			err(sbfd, "Unknown section type: %s\n", ss->name);
			DIE;
		}
	}
}

static void init_label_map(struct superbfd *sbfd)
{
	struct label_map *map;

	vec_init(&sbfd->maps);
	init_csyms(sbfd);
	init_callers(sbfd);

	struct symbol_hash csyms;
	symbol_hash_init(&csyms);

	asymbol **symp;
	for (symp = sbfd->syms.data;
	     symp < sbfd->syms.data + sbfd->syms.size; symp++) {
		asymbol *csym = canonical_symbol(sbfd, *symp);
		if (csym == NULL)
			continue;
		char *key = strprintf("%p", csym);
		asymbol **csymp = symbol_hash_lookup(&csyms, key, TRUE);
		free(key);
		if (*csymp != NULL)
			continue;
		*csymp = csym;

		map = vec_grow(&sbfd->maps, 1);
		map->csym = csym;
		map->count = 0;
		map->label = symbol_label(sbfd, csym);
	}

	struct label_mapp_hash label_maps;
	label_mapp_hash_init(&label_maps);
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		struct label_map **mapp =
		    label_mapp_hash_lookup(&label_maps, map->label, TRUE);
		if (*mapp == NULL) {
			*mapp = map;
			continue;
		}

		struct label_map *first_map = *mapp;
		if (first_map->count == 0)
			first_map->label = strprintf("%s~%d", map->label, 0);
		map->label = strprintf("%s~%d", map->label, ++first_map->count);
	}

	label_mapp_hash_init(&sbfd->maps_hash);
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		char *key = strprintf("%p", map->csym);
		struct label_map **mapp =
		    label_mapp_hash_lookup(&sbfd->maps_hash, key, TRUE);
		free(key);
		*mapp = map;
		map->orig_label = map->label;
	}
}

static const char *label_lookup(struct superbfd *sbfd, asymbol *sym)
{
	asymbol *csym = canonical_symbol(sbfd, sym);
	char *key = strprintf("%p", csym);
	struct label_map **mapp =
	    label_mapp_hash_lookup(&sbfd->maps_hash, key, FALSE);
	free(key);
	if (mapp == NULL)
		DIE;
	return (*mapp)->label;
}

static void print_label_changes(struct superbfd *sbfd)
{
	asection *sect;
	struct span *span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (strcmp(span->label, span->orig_label) != 0)
				debug1(sbfd, "Label change: %s -> %s\n",
				       span->label, span->orig_label);
		}
	}
}

static void label_map_set(struct superbfd *sbfd, const char *oldlabel,
			  const char *label)
{
	struct label_map *map;
	for (map = sbfd->maps.data;
	     map < sbfd->maps.data + sbfd->maps.size; map++) {
		if (strcmp(map->orig_label, oldlabel) == 0) {
			if (strcmp(map->orig_label, map->label) != 0 &&
			    strcmp(map->label, label) != 0)
				DIE;
			map->label = label;
			return;
		}
	}
	DIE;
}

static void change_initial_label(struct span *span, const char *label)
{
	struct superbfd *sbfd = span->ss->parent;
	span->label = label;
	span->orig_label = label;
	if (span->symbol) {
		asymbol *csym = canonical_symbol(sbfd, span->symbol);
		char *key = strprintf("%p", csym);
		struct label_map **mapp =
		    label_mapp_hash_lookup(&sbfd->maps_hash, key, FALSE);
		free(key);
		assert(mapp);
		(*mapp)->label = span->label;
		(*mapp)->orig_label = span->orig_label;
		span->symbol = NULL;
	}
}

static void init_callers(struct superbfd *sbfd)
{
	string_hash_init(&sbfd->callers);
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		arelent **relocp;
		for (relocp = ss->relocs.data;
		     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
			asymbol *sym = *(*relocp)->sym_ptr_ptr;
			unsigned long val =
			    sym->value + reloc_target_offset(ss, *relocp);
			char *key = strprintf("%s+%lx", sym->section->name,
					      val);
			const char **ret = string_hash_lookup(&sbfd->callers,
							      key, TRUE);
			free(key);
			asymbol *csym = canonical_symbol(sbfd, sect->symbol);
			if (*ret != NULL)
				*ret = "*multiple_callers*";
			else if (static_local_symbol(sbfd, csym))
				*ret = static_local_symbol(sbfd, csym);
			else
				*ret = sect->name;
		}
	}
}

static const char *find_caller(struct supersect *ss, asymbol *sym)
{
	char *key = strprintf("%s+%lx", sym->section->name,
			      (unsigned long)sym->value);
	const char **ret = string_hash_lookup(&ss->parent->callers, key, FALSE);
	free(key);

	if (ret == NULL)
		return "*no_caller*";
	return *ret;
}

static void init_csyms(struct superbfd *sbfd)
{
	asymbolpp_hash_init(&sbfd->csyms);

	asymbol **symp;
	for (symp = sbfd->syms.data; symp < sbfd->syms.data + sbfd->syms.size;
	     symp++) {
		asymbol *sym = *symp;
		if ((sym->flags & BSF_DEBUGGING) != 0)
			continue;
		char *key = strprintf("%s+%lx", sym->section->name,
				      (unsigned long)sym->value);
		asymbol ***csympp = asymbolpp_hash_lookup(&sbfd->csyms, key,
							  TRUE);
		free(key);
		if (*csympp == NULL) {
			*csympp = symp;
			continue;
		}
		asymbol *csym = **csympp;
		if ((csym->flags & BSF_GLOBAL) != 0)
			continue;
		if ((sym->flags & BSF_GLOBAL) != 0)
			*csympp = symp;
	}
}

static asymbol **symbolp_scan(struct supersect *ss, bfd_vma value)
{
	char *key = strprintf("%s+%lx", ss->name, (unsigned long)value);
	asymbol ***csympp =
	    asymbolpp_hash_lookup(&ss->parent->csyms, key, FALSE);
	free(key);
	if (csympp != NULL)
		return *csympp;

	/* For section symbols of sections containing no symbols, return the
	   section symbol that relocations are generated against */
	if (value == 0)
		return &ss->symbol;
	return NULL;
}

static asymbol **canonical_symbolp(struct superbfd *sbfd, asymbol *sym)
{
	if (bfd_is_const_section(sym->section)) {
		asymbol **csymp;
		for (csymp = sbfd->syms.data;
		     csymp < sbfd->syms.data + sbfd->syms.size; csymp++) {
			if (sym == *csymp)
				return csymp;
		}
		return NULL;
	}
	return symbolp_scan(fetch_supersect(sbfd, sym->section), sym->value);
}

static asymbol *canonical_symbol(struct superbfd *sbfd, asymbol *sym)
{
	if (bfd_is_const_section(sym->section))
		return sym;
	asymbol **symp = canonical_symbolp(sbfd, sym);
	return symp != NULL ? *symp : NULL;
}

static char *static_local_symbol(struct superbfd *sbfd, asymbol *sym)
{
	struct supersect *ss = fetch_supersect(sbfd, sym->section);
	if ((sym->flags & BSF_LOCAL) == 0 || (sym->flags & BSF_OBJECT) == 0)
		return NULL;
	char *dot = strrchr(sym->name, '.');
	if (dot == NULL || dot[1 + strspn(dot + 1, "0123546789")] != '\0')
		return NULL;
	char *basename = strndup(sym->name, dot - sym->name);

	/* Handle C.123.12345 symbols */
	dot = strrchr(basename, '.');
	if (dot != NULL && dot[1 + strspn(dot + 1, "0123546789")] == '\0')
		basename = strndup(basename, dot - basename);
	const char *caller;
	if (strcmp(basename, "__func__") == 0 ||
	    strcmp(basename, "__PRETTY_FUNCTION__") == 0)
		caller = (const char *)ss->contents.data + sym->value;
	else
		caller = find_caller(ss, sym);
	return strprintf("%s<%s>", basename, caller);
}

static char *symbol_label(struct superbfd *sbfd, asymbol *sym)
{
	const char *filename = sbfd->abfd->filename;
	char *c = strstr(filename, ".KSPLICE");
	int flen = (c == NULL ? strlen(filename) : c - filename);

	char *label;
	if (bfd_is_und_section(sym->section) || (sym->flags & BSF_GLOBAL) != 0) {
		label = strdup(sym->name);
	} else if (bfd_is_const_section(sym->section)) {
		label = strprintf("%s<%.*s>", sym->name, flen, filename);
	} else {
		asymbol *gsym = canonical_symbol(sbfd, sym);

		if (gsym == NULL)
			label = strprintf("%s+%lx<%.*s>",
					  sym->section->name,
					  (unsigned long)sym->value,
					  flen, filename);
		else if ((gsym->flags & BSF_GLOBAL) != 0)
			label = strdup(gsym->name);
		else if (static_local_symbol(sbfd, gsym))
			label = strprintf("%s+%lx<%.*s>",
					  static_local_symbol(sbfd, gsym),
					  (unsigned long)sym->value,
					  flen, filename);
		else
			label = strprintf("%s<%.*s>",
					  gsym->name, flen, filename);
	}

	return label;
}

static void keep_span(struct span *span)
{
	span->keep = true;
	span->ss->keep = true;
}

static struct span *new_span(struct supersect *ss, bfd_vma start, bfd_vma size)
{
	struct span *span = vec_grow(&ss->spans, 1);
	span->size = size;
	span->contents_size = size;
	span->start = start;
	span->ss = ss;
	span->keep = true;
	span->new = false;
	span->patch = false;
	span->bugpatch = false;
	span->datapatch = false;
	span->precallable = strstarts(ss->name, ".ksplice_call_pre_apply") ||
	    strstarts(ss->name, ".ksplice_call_check_apply") ||
	    strstarts(ss->name, ".ksplice_call_fail_apply") ||
	    strstarts(ss->name, ".ksplice_call_post_remove");
	span->match = NULL;
	vec_init(&span->entry_points);
	span->shift = 0;
	asymbol **symp = symbolp_scan(ss, span->start);
	if (symp != NULL) {
		span->symbol = *symp;
		span->label = label_lookup(ss->parent, span->symbol);
	} else {
		span->symbol = NULL;
		const char *label = label_lookup(ss->parent, ss->symbol);
		if (span->start != 0)
			span->label = strprintf("%s<span:%lx>", label,
						(unsigned long)span->start);
		else
			span->label = label;
	}
	span->orig_label = span->label;
	return span;
}

static void initialize_string_spans(struct supersect *ss)
{
	const char *str;
	for (str = ss->contents.data;
	     (void *)str < ss->contents.data + ss->contents.size;) {
		bfd_vma start = (unsigned long)str -
		    (unsigned long)ss->contents.data;
		bfd_vma size = strlen(str) + 1;
		bfd_vma contents_size = size;
		while ((start + size) % (1 << ss->alignment) != 0 &&
		       start + size < ss->contents.size) {
			/* Some string sections, like __ksymtab_strings, only
			   align some strings with the declared alignment */
			if (str[size] != '\0')
				break;
			size++;
		}
		struct span *span = new_span(ss, start, size);
		span->contents_size = contents_size;
		str += size;
	}
}

static int compare_ulongs(const void *va, const void *vb)
{
	const unsigned long *a = va, *b = vb;
	return *a - *b;
}

static void initialize_table_spans(struct superbfd *sbfd,
				   struct table_section *s)
{
	asection *isection = bfd_get_section_by_name(sbfd->abfd, s->sect);
	if (isection == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, isection);
	if (ss->alignment < ffs(s->entry_align) - 1)
		ss->alignment = ffs(s->entry_align) - 1;

	asection *other_sect = NULL;
	if (s->other_sect != NULL)
		other_sect = bfd_get_section_by_name(sbfd->abfd, s->other_sect);
	struct supersect *other_ss = NULL;
	if (other_sect != NULL)
		other_ss = fetch_supersect(sbfd, other_sect);

	asection *crc_sect = NULL;
	if (s->crc_sect != NULL)
		crc_sect = bfd_get_section_by_name(sbfd->abfd, s->crc_sect);
	struct supersect *crc_ss = NULL;
	if (crc_sect != NULL)
		crc_ss = fetch_supersect(sbfd, crc_sect);

	struct ulong_vec offsets;
	vec_init(&offsets);

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += s->entry_size) {
		struct span *span = new_span(ss, addr_offset(ss, entry),
					     s->entry_size);
		if (s->entry_contents_size != 0)
			span->contents_size = s->entry_contents_size;
		if ((span->symbol == NULL ||
		     (span->symbol->flags & BSF_SECTION_SYM) != 0) &&
		    s->has_addr) {
			arelent *reloc = find_reloc(ss, entry + s->addr_offset);
			assert(reloc);
			struct span *target_span = reloc_target_span(ss, reloc);
			assert(target_span);
			asymbol *sym = *reloc->sym_ptr_ptr;
			unsigned long val = sym->value +
			    reloc_target_offset(ss, reloc) -
			    (target_span->start + target_span->shift);
			char *label = strprintf("%s<target:%s+%lx>", ss->name,
						target_span->label, val);
			change_initial_label(span, label);
		}

		if (other_sect != NULL) {
			asymbol *sym;
			bfd_vma offset = read_reloc(ss, entry + s->other_offset,
						    sizeof(void *), &sym);
			if (sym->section == other_sect) {
				assert(offset >= 0 &&
				       offset < other_ss->contents.size);
				*vec_grow(&offsets, 1) = offset;
			}
		}

		if (crc_sect != NULL)
			new_span(crc_ss, addr_offset(ss, entry) / s->entry_size
				 * s->crc_size, s->crc_size);

		if (ss->type == SS_TYPE_EXPORT) {
			const char *symname = read_string(ss, entry +
							  s->other_offset);
			char *label = strprintf("%s:%s", ss->name, symname);
			change_initial_label(span, label);
		}
	}

	if (other_sect == NULL)
		return;

	*vec_grow(&offsets, 1) = 0;
	qsort(offsets.data, offsets.size, sizeof(*offsets.data),
	      compare_ulongs);
	*vec_grow(&offsets, 1) = other_ss->contents.size;

	unsigned long *off;
	for (off = offsets.data; off < offsets.data + offsets.size - 1; off++) {
		if (*off != *(off + 1))
			new_span(other_ss, *off, *(off + 1) - *off);
	}
}

static void initialize_table_section_spans(struct superbfd *sbfd)
{
	struct supersect *tables_ss =
	    fetch_supersect(offsets_sbfd,
			    bfd_get_section_by_name(offsets_sbfd->abfd,
						    ".ksplice_table_sections"));
	const struct table_section *ts;
	struct table_section s;
	for (ts = tables_ss->contents.data;
	     (void *)ts < tables_ss->contents.data + tables_ss->contents.size;
	     ts++) {
		s = *ts;
		s.sect = read_string(tables_ss, &ts->sect);
		s.other_sect = read_string(tables_ss, &ts->other_sect);
		s.crc_sect = read_string(tables_ss, &ts->crc_sect);
		initialize_table_spans(sbfd, &s);
	}
}

static void initialize_ksplice_call_spans(struct supersect *ss)
{
	arelent **relocp;
	for (relocp = ss->relocs.data;
	     relocp < ss->relocs.data + ss->relocs.size; relocp++) {
		arelent *reloc = *relocp;
		new_span(ss, reloc->address, bfd_get_reloc_size(reloc->howto));
		/* the span labels should already be unique */
	}
}

static void initialize_spans(struct superbfd *sbfd)
{
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		if (is_table_section(sect->name, true, true) && mode("keep"))
			continue;

		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (ss->type == SS_TYPE_STRING)
			initialize_string_spans(ss);
		else if (ss->type == SS_TYPE_KSPLICE_CALL)
			initialize_ksplice_call_spans(ss);
		else
			new_span(ss, 0, ss->contents.size);
	}
	if (mode("keep"))
		initialize_table_section_spans(sbfd);
}

/* Returns the span pointed to by the relocation at span->start + offset */
static struct span *span_offset_target_span(struct span *span, int offset)
{
	void *entry = span->ss->contents.data + span->start;
	arelent *reloc = find_reloc(span->ss, entry + offset);
	if (reloc == NULL)
		return NULL;
	return reloc_target_span(span->ss, reloc);
}

struct span *reloc_target_span(struct supersect *ss, arelent *reloc)
{
	asymbol *sym_ptr = *reloc->sym_ptr_ptr;
	if (bfd_is_const_section(sym_ptr->section))
		return NULL;

	bfd_vma addend = sym_ptr->value;
	if ((sym_ptr->flags & BSF_SECTION_SYM) != 0)
		addend += reloc_target_offset(ss, reloc);

	struct supersect *sym_ss =
	    fetch_supersect(ss->parent, sym_ptr->section);
	struct span *span, *target_span = sym_ss->spans.data;
	for (span = sym_ss->spans.data;
	     span < sym_ss->spans.data + sym_ss->spans.size; span++) {
		if (addend >= span->start && addend < span->start + span->size)
			target_span = span;
	}
	return target_span;
}

static bfd_vma reloc_target_offset(struct supersect *ss, arelent *reloc)
{
	bfd_vma offset = reloc_offset(ss, reloc);
	if (reloc->howto->pc_relative) {
		if ((ss->flags & SEC_CODE) != 0)
			return offset + bfd_get_reloc_size(reloc->howto);

		const struct table_section *ts = get_table_section(ss->name);
		if (ts != NULL && ts->relative_addr &&
		    reloc->address % ts->entry_size == ts->addr_offset)
			return offset - ts->addr_offset;
		if (ts != NULL && ts->relative_other &&
		    reloc->address % ts->entry_size == ts->other_offset)
			return offset - ts->other_offset;

		DIE;
	}
	return offset;
}

struct span *find_span(struct supersect *ss, bfd_size_type address)
{
	struct span *span;
	for (span = ss->spans.data; span < ss->spans.data + ss->spans.size;
	     span++) {
		if (address >= span->start &&
		    address < span->start + span->size)
			return span;
	}
	/* Deal with empty BSS sections */
	if (ss->contents.size == 0 && ss->spans.size > 0)
		return ss->spans.data;
	/* Deal with section end pointers */
	if (address == ss->contents.size && ss->spans.size == 1)
		return ss->spans.data;
	return NULL;
}

void compute_span_shifts(struct superbfd *sbfd)
{
	asection *sect;
	struct span *span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (!ss->keep)
			continue;
		bfd_size_type offset = 0;
		for (span = ss->spans.data;
		     span < ss->spans.data + ss->spans.size; span++) {
			if (!span->keep)
				continue;
			span->shift = offset - span->start;
			offset += span->size;
		}
	}
}

void remove_unkept_spans(struct superbfd *sbfd)
{
	asection *sect;
	struct span *span;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		delete_obsolete_relocs(ss);
		struct arelentp_vec orig_relocs;
		vec_move(&orig_relocs, &ss->relocs);
		arelent **relocp, *reloc;
		for (relocp = orig_relocs.data;
		     relocp < orig_relocs.data + orig_relocs.size; relocp++) {
			reloc = *relocp;
			asymbol *sym = *reloc->sym_ptr_ptr;
			span = reloc_target_span(ss, reloc);
			if ((span != NULL && span->keep && span->shift == 0) ||
			    bfd_is_const_section(sym->section)) {
				*vec_grow(&ss->relocs, 1) = reloc;
				continue;
			}
			struct supersect *sym_ss =
			    fetch_supersect(sbfd, sym->section);
			if (span != NULL && (sym->flags & BSF_SECTION_SYM) == 0
			    && find_span(sym_ss, sym->value) != span) {
				err(sbfd, "Spans for symbol %s and relocation "
				    "target do not match in sect %s\n",
				    sym->name, sym_ss->name);
				DIE;
			}
			if (span != NULL && span->keep) {
				arelent *new_reloc = malloc(sizeof(*new_reloc));
				*new_reloc = *reloc;
				new_reloc->addend = reloc_offset(ss, reloc);
				new_reloc->addend += span->shift;
				*vec_grow(&ss->new_relocs, 1) = new_reloc;
			}
		}
	}

	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect), orig_ss;
		if (!ss->keep)
			continue;
		supersect_move(&orig_ss, ss);
		vec_init(&ss->spans);
		for (span = orig_ss.spans.data;
		     span < orig_ss.spans.data + orig_ss.spans.size; span++) {
			if (!span->keep)
				continue;
			struct span *new_span = vec_grow(&ss->spans, 1);
			*new_span = *span;
			new_span->start = span->start + span->shift;
			new_span->shift = 0;
			sect_copy(ss, sect_do_grow(ss, 1, span->size, 1),
				  &orig_ss, orig_ss.contents.data + span->start,
				  span->size);
		}
	}
}

static void init_objmanip_superbfd(struct superbfd *sbfd)
{
	init_label_map(sbfd);
	initialize_supersect_types(sbfd);
	initialize_spans(sbfd);
	load_options(sbfd);
	compute_entry_points(sbfd);
}

void mangle_section_name(struct superbfd *sbfd, const char *name)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd, name);
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);
	ss->name = strprintf(".ksplice_pre.%s", ss->name);
}

static void write_bugline_patches(struct superbfd *sbfd)
{
	const struct table_section *ts = get_table_section("__bug_table");
	asection *sect = bfd_get_section_by_name(sbfd->abfd, "__bug_table");
	if (sect == NULL)
		return;
	struct supersect *ss = fetch_supersect(sbfd, sect);
	assert(ts != NULL);

	void *entry;
	for (entry = ss->contents.data;
	     entry < ss->contents.data + ss->contents.size;
	     entry += ts->entry_size) {
		struct span *span = find_span(ss, addr_offset(ss, entry));
		assert(span != NULL);
		if (!span->bugpatch)
			continue;
		arelent *reloc = find_reloc(ss, entry + ts->addr_offset);
		assert(reloc != NULL);
		asymbol *sym = *reloc->sym_ptr_ptr;
		assert(!bfd_is_const_section(sym->section));
		struct supersect *kpatch_ss =
		    make_section(sbfd, ".ksplice_patches%s",
				 sym->section->name);

		bfd_vma offset, start = 0;
		for (offset = 0; offset <= span->size; offset++) {
			if (offset != span->size &&
			    !part_of_reloc(ss, span->start + offset))
				continue;
			if (start == offset) {
				start++;
				continue;
			}
			/* an interval of non-relocations just passed */
			struct ksplice_patch *kpatch =
			    sect_grow(kpatch_ss, 1, struct ksplice_patch);
			write_ksplice_patch_reloc
			    (kpatch_ss, sym->section->name, &kpatch->oldaddr,
			     sizeof(kpatch->oldaddr), span->label, start);

			char *data = write_patch_storage(kpatch_ss, kpatch,
							 offset - start, NULL);
			memcpy(data, entry + start, offset - start);
			kpatch->type = KSPLICE_PATCH_DATA;
			start = offset + 1;
		}
	}
}

void *write_patch_storage(struct supersect *ss, struct ksplice_patch *kpatch,
			  size_t size, struct supersect **data_ssp)
{
	struct supersect *data_ss = make_section(ss->parent,
						 ".ksplice_patch_data");
	char *saved = sect_do_grow(data_ss, 1, size, 1);
	write_reloc(ss, &kpatch->saved, &data_ss->symbol,
		    addr_offset(data_ss, saved));
	char *data = sect_do_grow(data_ss, 1, size, 1);
	write_reloc(ss, &kpatch->contents, &data_ss->symbol,
		    addr_offset(data_ss, data));
	kpatch->size = size;
	if (data_ssp != NULL)
		*data_ssp = data_ss;
	return data;
}
