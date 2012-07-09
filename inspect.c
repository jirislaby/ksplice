/*  Copyright (C) 2008-2009  Ksplice, Inc.
 *  Authors: Anders Kaseorg, Tim Abbott, Jeff Arnold
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

/* Always define KSPLICE_STANDALONE, even if you're using integrated Ksplice.
   inspect won't compile without it. */
#define KSPLICE_STANDALONE

#define _GNU_SOURCE
#include "objcommon.h"
#include "kmodsrc/ksplice.h"
#include <stdio.h>

char *str_pointer(struct supersect *ss, void *const *addr);

struct kreloc_section {
	struct supersect *ss;
	const struct ksplice_reloc *reloc;
};

#define kreloc_section_init(ks) *(ks) = NULL
DEFINE_HASH_TYPE(struct kreloc_section *, kreloc_section_hash,
		 kreloc_section_hash_init, kreloc_section_hash_free,
		 kreloc_section_hash_lookup, kreloc_section_init);
struct kreloc_section_hash ksplice_relocs;

char *str_ulong_vec(struct supersect *ss, const unsigned long *const *datap,
		    const unsigned long *sizep)
{
	struct supersect *data_ss;
	const unsigned long *data =
	    read_pointer(ss, (void *const *)datap, &data_ss);
	unsigned long size = read_num(ss, sizep);

	char *buf = NULL;
	size_t bufsize = 0;
	FILE *fp = open_memstream(&buf, &bufsize);
	fprintf(fp, "[ ");
	size_t i;
	for (i = 0; i < size; ++i)
		fprintf(fp, "%lx ", read_num(data_ss, &data[i]));
	fprintf(fp, "]");
	fclose(fp);
	return buf;
}

static const struct ksplice_reloc *
find_ksplice_reloc(struct supersect *ss, void *const *addr,
		   struct supersect **reloc_ss)
{
	char *key = strprintf("%p", addr);
	struct kreloc_section **ksp =
	    kreloc_section_hash_lookup(&ksplice_relocs, key, FALSE);
	free(key);
	if (ksp == NULL)
		return NULL;
	*reloc_ss = (*ksp)->ss;
	return (*ksp)->reloc;
}

char *str_ksplice_symbol(struct supersect *ss,
			 const struct ksplice_symbol *ksymbol)
{
	return strprintf("%s (%s)",
			 read_string(ss, &ksymbol->label),
			 read_string(ss, &ksymbol->name));
}

char *str_ksplice_symbolp(struct supersect *ptr_ss,
			  struct ksplice_symbol *const *ksymbolp)
{
	asymbol *sym;
	bfd_vma offset = read_reloc(ptr_ss, ksymbolp, sizeof(*ksymbolp), &sym);
	if (bfd_is_const_section(sym->section))
		return strprintf("*(%s)",
				 str_pointer(ptr_ss, (void *const *)ksymbolp));
	struct supersect *ksymbol_ss = fetch_supersect(ptr_ss->parent,
						       sym->section);
	return str_ksplice_symbol(ksymbol_ss, ksymbol_ss->contents.data +
				  sym->value + offset);
}

char *str_pointer(struct supersect *ss, void *const *addr)
{
	asymbol *sym;
	struct supersect *kreloc_ss;
	const struct ksplice_reloc *kreloc =
	    find_ksplice_reloc(ss, addr, &kreloc_ss);
	if (kreloc == NULL) {
		bfd_vma offset = read_reloc(ss, addr, sizeof(*addr), &sym);
		return strprintf("%s+%lx", sym->name, (unsigned long)offset);
	} else {
		return strprintf("[%s]+%lx",
				 str_ksplice_symbolp(kreloc_ss,
						     &kreloc->symbol),
				 kreloc->target_addend);
	}
}

static const char *str_howto_type(const struct ksplice_reloc_howto *howto)
{
	switch (howto->type) {
	case KSPLICE_HOWTO_RELOC:
		return "reloc";
	case KSPLICE_HOWTO_RELOC_PATCH:
		return "reloc(patch)";
	case KSPLICE_HOWTO_TIME:
		return "time";
	case KSPLICE_HOWTO_DATE:
		return "date";
	case KSPLICE_HOWTO_BUG:
		return "bug";
	case KSPLICE_HOWTO_EXTABLE:
		return "extable";
	case KSPLICE_HOWTO_SYMBOL:
		return "symbol";
	default:
		return "unknown";
	}
}

void show_ksplice_reloc(struct supersect *ss,
			const struct ksplice_reloc *kreloc)
{
	struct supersect *khowto_ss;
	const struct ksplice_reloc_howto *khowto =
	    read_pointer(ss, (void *const *)&kreloc->howto, &khowto_ss);
	printf("  blank_addr: %s  size: %x\n"
	       "  type: %s\n"
	       "  symbol: %s\n"
	       "  insn_addend: %lx\n"
	       "  target_addend: %lx\n"
	       "  pcrel: %x  dst_mask: %lx  rightshift: %x  signed_addend: %x\n"
	       "\n",
	       str_pointer(ss, (void *const *)&kreloc->blank_addr),
	       read_num(khowto_ss, &khowto->size),
	       str_howto_type(khowto),
	       str_ksplice_symbolp(ss, &kreloc->symbol),
	       read_num(ss, &kreloc->insn_addend),
	       read_num(ss, &kreloc->target_addend),
	       read_num(khowto_ss, &khowto->pcrel),
	       read_num(khowto_ss, &khowto->dst_mask),
	       read_num(khowto_ss, &khowto->rightshift),
	       read_num(khowto_ss, &khowto->signed_addend));
}

void show_ksplice_relocs(struct supersect *kreloc_ss)
{
	const struct ksplice_reloc *kreloc;
	for (kreloc = kreloc_ss->contents.data; (void *)kreloc <
	     kreloc_ss->contents.data + kreloc_ss->contents.size; kreloc++)
		show_ksplice_reloc(kreloc_ss, kreloc);
}

void show_ksplice_section_flags(const struct ksplice_section *ksect)
{
	printf("  flags:");
	if (ksect->flags & KSPLICE_SECTION_RODATA)
		printf(" rodata");
	if (ksect->flags & KSPLICE_SECTION_TEXT)
		printf(" text");
	if (ksect->flags & KSPLICE_SECTION_DATA)
		printf(" data");
	if (ksect->flags & KSPLICE_SECTION_MATCH_DATA_EARLY)
		printf(" match_early");
	printf("\n");
}

void show_ksplice_section(struct supersect *ss,
			  const struct ksplice_section *ksect)
{
	printf("  symbol: %s\n"
	       "  address: %s  size: %lx\n",
	       str_ksplice_symbolp(ss, &ksect->symbol),
	       str_pointer(ss, (void *const *)&ksect->address),
	       read_num(ss, &ksect->size));
	show_ksplice_section_flags(ksect);
	printf("\n");
}

void show_ksplice_sections(struct supersect *ksect_ss)
{
	struct ksplice_section *ksect;
	for (ksect = ksect_ss->contents.data; (void *)ksect <
	     ksect_ss->contents.data + ksect_ss->contents.size; ksect++)
		show_ksplice_section(ksect_ss, ksect);
}

const char *str_ksplice_patch_type(struct supersect *ss,
				   const struct ksplice_patch *kpatch)
{
	const char *const *strp;
	struct supersect *data_ss;
	switch(kpatch->type) {
	case KSPLICE_PATCH_TEXT:
		return strprintf("text\n  repladdr: %s", str_pointer
				 (ss, (void *const *)&kpatch->repladdr));
	case KSPLICE_PATCH_DATA:
		return strprintf("data\n  size: %x", kpatch->size);
	case KSPLICE_PATCH_EXPORT:
		strp = read_pointer(ss, &kpatch->contents, &data_ss);
		return strprintf("export\n  newname: %s",
				 read_string(data_ss, strp));
	default:
		return "unknown";
	}
}

void show_ksplice_patch(struct supersect *ss,
			const struct ksplice_patch *kpatch)
{
	printf("  type: %s\n"
	       "  oldaddr: %s\n\n",
	       str_ksplice_patch_type(ss, kpatch),
	       str_pointer(ss, (void *const *)&kpatch->oldaddr));
}

void show_ksplice_patches(struct supersect *kpatch_ss)
{
	const struct ksplice_patch *kpatch;
	for (kpatch = kpatch_ss->contents.data; (void *)kpatch <
	     kpatch_ss->contents.data + kpatch_ss->contents.size; kpatch++)
		show_ksplice_patch(kpatch_ss, kpatch);
}

void show_ksplice_call(struct supersect *ss, void *const *kcall)
{
	printf("%s\n", str_pointer(ss, kcall));
}

void show_ksplice_calls(struct supersect *kcall_ss)
{
	void *const *kcall;
	for (kcall = kcall_ss->contents.data; (void *)kcall <
	     kcall_ss->contents.data + kcall_ss->contents.size; kcall++)
		show_ksplice_call(kcall_ss, kcall);
}

void show_ksplice_system_map(struct supersect *ss,
			     const struct ksplice_system_map *smap)
{
	printf("%s %s\n",
	       read_string(ss, &smap->label),
	       str_ulong_vec(ss, &smap->candidates, &smap->nr_candidates));
}

void show_ksplice_system_maps(struct supersect *smap_ss)
{
	const struct ksplice_system_map *smap;
	for (smap = smap_ss->contents.data;
	     (void *)smap < smap_ss->contents.data + smap_ss->contents.size;
	     smap++)
		show_ksplice_system_map(smap_ss, smap);
}

struct inspect_section {
	const char *prefix;
	const char *header;
	const char *notfound;
	void (*show)(struct supersect *ss);
};

const struct inspect_section inspect_sections[] = {
	{
		.prefix = ".ksplice_init_relocs",
		.header = "KSPLICE INIT RELOCATIONS",
		.notfound = "No ksplice init relocations.\n",
		.show = show_ksplice_relocs,
	},
	{
		.prefix = ".ksplice_relocs",
		.header = "KSPLICE RELOCATIONS",
		.notfound = "No ksplice relocations.\n",
		.show = show_ksplice_relocs,
	},
	{
		.prefix = ".ksplice_sections",
		.header = "KSPLICE SECTIONS",
		.notfound = "No ksplice sections.\n",
		.show = show_ksplice_sections,
	},
	{
		.prefix = ".ksplice_patches",
		.header = "KSPLICE PATCHES",
		.notfound = "No ksplice patches.\n",
		.show = show_ksplice_patches,
	},
	{
		.prefix = ".ksplice_call",
		.header = "KSPLICE CALLS",
		.notfound = "No ksplice calls.\n",
		.show = show_ksplice_calls,
	},
	{
		.prefix = ".ksplice_system_map",
		.header = "KSPLICE SYSTEM.MAP",
		.notfound = "No ksplice System.map.\n",
		.show = show_ksplice_system_maps,
	},
}, *const inspect_sections_end = *(&inspect_sections + 1);

static void load_ksplice_reloc_offsets(struct superbfd *sbfd)
{
	kreloc_section_hash_init(&ksplice_relocs);

	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (!strstarts(ss->name, ".ksplice_relocs") &&
		    !strstarts(ss->name, ".ksplice_init_relocs"))
			continue;
		struct ksplice_reloc *kreloc;
		for (kreloc = ss->contents.data;
		     (void *)kreloc < ss->contents.data + ss->contents.size;
		     kreloc++) {
			const struct ksplice_reloc_howto *khowto =
			    read_pointer(ss, (void *const *)&kreloc->howto,
					 NULL);
			if (khowto->size == 0)
				continue;

			struct supersect *sym_ss;
			const void *ptr =
			    read_pointer(ss, (void *const *)&kreloc->blank_addr,
					 &sym_ss);
			char *key = strprintf("%p", ptr);
			struct kreloc_section *ks, **ksp =
			    kreloc_section_hash_lookup(&ksplice_relocs, key,
						       TRUE);
			free(key);
			assert(*ksp == NULL);
			ks = malloc(sizeof(*ks));
			*ksp = ks;
			ks->reloc = kreloc;
			ks->ss = ss;
		}
	}
}

static void show_inspect_section(struct superbfd *sbfd,
				 const struct inspect_section *isect)
{
	bool found = false;
	asection *sect;
	for (sect = sbfd->abfd->sections; sect != NULL; sect = sect->next) {
		struct supersect *ss = fetch_supersect(sbfd, sect);
		if (strstarts(ss->name, isect->prefix) &&
		    ss->contents.size != 0) {
			printf("%s IN [%s]:\n", isect->header, sect->name);
			found = true;
			isect->show(ss);
		}
	}
	if (!found)
		printf("%s", isect->notfound);
	printf("\n");
}

int main(int argc, char *argv[])
{
	bfd *ibfd;

	assert(argc >= 1);
	bfd_init();
	ibfd = bfd_openr(argv[1], NULL);
	assert(ibfd);

	char **matching;
	assert(bfd_check_format_matches(ibfd, bfd_object, &matching));

	struct superbfd *sbfd = fetch_superbfd(ibfd);
	load_ksplice_reloc_offsets(sbfd);
	const struct inspect_section *isect;
	for (isect = inspect_sections; isect < inspect_sections_end; isect++)
		show_inspect_section(sbfd, isect);

	return 0;
}
