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

#include <linux/thread_info.h>
#define KSPLICE_IP(x) thread_saved_pc(x)
#define KSPLICE_SP(x) thread_saved_fp(x)

static struct ksplice_symbol trampoline_symbol = {
	.name = NULL,
	.label = "<trampoline>",
};

static const struct ksplice_reloc_howto trampoline_howto = {
	.type = KSPLICE_HOWTO_RELOC,
	.pcrel = 1,
	.size = 4,
	.dst_mask = 0x00ffffffL,
	.rightshift = 2,
	.signed_addend = 1,
};

static const struct ksplice_reloc trampoline_reloc = {
	.symbol = &trampoline_symbol,
	.insn_addend = -8,
	.target_addend = 0,
	.howto = &trampoline_howto,
};

static abort_t trampoline_target(struct ksplice_mod_change *change,
				 unsigned long addr, unsigned long *new_addr)
{
	abort_t ret;
	uint32_t word;
	if (probe_kernel_read(&word, (void *)addr, sizeof(word)) == -EFAULT)
		return NO_MATCH;

	if ((word & 0xff000000) != 0xea000000)
		return NO_MATCH;

	ret = read_reloc_value(change, &trampoline_reloc, addr, new_addr);
	if (ret != OK)
		return ret;

	*new_addr += addr;
	return OK;
}

static abort_t prepare_trampoline(struct ksplice_mod_change *change,
				  struct ksplice_patch *p)
{
	p->size = 4;
	*(uint32_t *)p->contents = 0xea000000;
	return write_reloc_value(change, &trampoline_reloc,
				 (unsigned long)p->contents,
				 p->repladdr - p->oldaddr);
}

static abort_t handle_paravirt(struct ksplice_mod_change *change,
			       unsigned long pre_addr, unsigned long run_addr,
			       int *matched)
{
	*matched = 0;
	return OK;
}

static bool valid_stack_ptr(const struct thread_info *tinfo, const void *p)
{
	return p > (const void *)tinfo
	    && p <= (const void *)tinfo + THREAD_SIZE - sizeof(long);
}
