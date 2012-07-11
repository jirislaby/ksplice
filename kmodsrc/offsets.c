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

#include <generated/compile.h>
#include <generated/utsrelease.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/tracepoint.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#endif /* CONFIG_PARAVIRT */
#include <asm/uaccess.h>
#include "offsets.h"

const struct ksplice_config config
    __attribute__((section(".ksplice_config"))) = {
/* Introduction of .cpuinit, .devinit, .meminit sections */
#ifndef CONFIG_HOTPLUG
	.ignore_devinit = 1,
#endif /* !CONFIG_HOTPLUG */
#ifndef CONFIG_HOTPLUG_CPU
	.ignore_cpuinit = 1,
#endif /* !CONFIG_HOTPLUG_CPU */
#ifndef CONFIG_MEMORY_HOTPLUG
	.ignore_meminit = 1,
#endif /* !CONFIG_MEMORY_HOTPLUG */
};

#define FIELD_ENDOF(t, f) (offsetof(t, f) + FIELD_SIZEOF(t, f))

const struct table_section table_sections[]
    __attribute__((section(".ksplice_table_sections"))) = {
#ifdef CONFIG_X86
	{
		.sect = ".altinstructions",
		.entry_size = sizeof(struct alt_instr),
		.entry_contents_size = FIELD_ENDOF(struct alt_instr,
				replacementlen),
		.entry_align = __alignof__(struct alt_instr),
		.has_addr = 1,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
		.relative_addr = 1,
		.addr_offset = offsetof(struct alt_instr, instr_offset),
		.relative_other = 1,
		.other_sect = ".altinstr_replacement",
		.other_offset = offsetof(struct alt_instr, repl_offset),
#else
		.addr_offset = offsetof(struct alt_instr, instr),
		.other_sect = ".altinstr_replacement",
		.other_offset = offsetof(struct alt_instr, replacement),
#endif
	},
#endif /* CONFIG_X86 */
#ifdef CONFIG_GENERIC_BUG
	{
		.sect = "__bug_table",
		.entry_size = sizeof(struct bug_entry),
		.entry_contents_size = FIELD_ENDOF(struct bug_entry, flags),
		.entry_align = __alignof__(struct bug_entry),
		.has_addr = 1,
#ifdef CONFIG_GENERIC_BUG_RELATIVE_POINTERS
		.relative_addr = 1,
		.addr_offset = offsetof(struct bug_entry, bug_addr_disp),
		.relative_other = 1,
		.other_offset = offsetof(struct bug_entry, file_disp),
#else
		.addr_offset = offsetof(struct bug_entry, bug_addr),
#endif
	},
#endif /* CONFIG_GENERIC_BUG */
	{
		.sect = "__ex_table",
		.entry_size = sizeof(struct exception_table_entry),
		.entry_align = __alignof__(struct exception_table_entry),
		.has_addr = 1,
		.addr_offset = offsetof(struct exception_table_entry, insn),
		.other_sect = ".fixup",
		.other_offset = offsetof(struct exception_table_entry, fixup),
	},
	{
		.sect = "__tracepoints",
		.entry_size = sizeof(struct tracepoint),
		.entry_align = __alignof__(struct tracepoint),
		.other_sect = "__tracepoints_strings",
		.other_offset = offsetof(struct tracepoint, name),
	},
#ifdef CONFIG_PARAVIRT
	{
		.sect = ".parainstructions",
		.entry_size = sizeof(struct paravirt_patch_site),
		.entry_contents_size = FIELD_ENDOF(struct paravirt_patch_site,
						   clobbers),
		.entry_align = __alignof__(struct paravirt_patch_site),
		.has_addr = 1,
		.addr_offset = offsetof(struct paravirt_patch_site, instr),
	},
#endif /* CONFIG_PARAVIRT */
	{
		.sect = ".smp_locks",
		.entry_size = sizeof(u32),
		.entry_align = 4,
		.has_addr = 1,
		.relative_addr = 1,
		.addr_offset = 0,
	},
	{
		.sect = "__ksymtab",
		.entry_size = sizeof(struct kernel_symbol),
		.entry_align = __alignof__(struct kernel_symbol),
		.other_offset = offsetof(struct kernel_symbol, name),
#ifdef CONFIG_MODVERSIONS
		.crc_size = sizeof(unsigned long),
		.crc_sect = "__kcrctab",
#endif /* CONFIG_MODVERSIONS */
	},
	{
		.sect = "__ksymtab_gpl",
		.entry_size = sizeof(struct kernel_symbol),
		.entry_align = __alignof__(struct kernel_symbol),
		.other_offset = offsetof(struct kernel_symbol, name),
#ifdef CONFIG_MODVERSIONS
		.crc_size = sizeof(unsigned long),
		.crc_sect = "__kcrctab_gpl",
#endif /* CONFIG_MODVERSIONS */
	},
#ifdef CONFIG_UNUSED_SYMBOLS
/* f71d20e961474dde77e6558396efb93d6ac80a4b was after 2.6.17 */
	{
		.sect = "__ksymtab_unused_gpl",
		.entry_size = sizeof(struct kernel_symbol),
		.entry_align = __alignof__(struct kernel_symbol),
		.other_offset = offsetof(struct kernel_symbol, name),
#ifdef CONFIG_MODVERSIONS
		.crc_size = sizeof(unsigned long),
		.crc_sect = "__kcrctab_unused_gpl",
#endif /* CONFIG_MODVERSIONS */
	},
	{
		.sect = "__ksymtab_unused",
		.entry_size = sizeof(struct kernel_symbol),
		.entry_align = __alignof__(struct kernel_symbol),
		.other_offset = offsetof(struct kernel_symbol, name),
#ifdef CONFIG_MODVERSIONS
		.crc_size = sizeof(unsigned long),
		.crc_sect = "__kcrctab_unused",
#endif /* CONFIG_MODVERSIONS */
	},
#endif /* CONFIG_UNUSED_SYMBOLS */
	{
		.sect = "__ksymtab_gpl_future",
		.entry_size = sizeof(struct kernel_symbol),
		.entry_align = __alignof__(struct kernel_symbol),
		.other_offset = offsetof(struct kernel_symbol, name),
#ifdef CONFIG_MODVERSIONS
		.crc_size = sizeof(unsigned long),
		.crc_sect = "__kcrctab_gpl_future",
#endif /* CONFIG_MODVERSIONS */
	},
};

const char *__attribute__((section(".uts_sysname"))) sysname = UTS_SYSNAME;
const char *__attribute__((section(".uts_release"))) release = UTS_RELEASE;
const char *__attribute__((section(".uts_version"))) version = UTS_VERSION;
const char *__attribute__((section(".uts_machine"))) machine = UTS_MACHINE;
