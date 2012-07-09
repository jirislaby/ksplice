/*  Copyright (C) 2008-2009  Ksplice, Inc.
 *  Authors: Tim Abbott, Anders Kaseorg, Jeff Arnold
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

#define _GNU_SOURCE
#include "objcommon.h"
#include <stdio.h>

static void print_section(struct superbfd *sbfd, const char *fieldname,
			  const char *sectname)
{
	asection *sect = bfd_get_section_by_name(sbfd->abfd, sectname);
	assert(sect != NULL);
	struct supersect *ss = fetch_supersect(sbfd, sect);
	printf("%s: %s\n", fieldname, read_string(ss, ss->contents.data));
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

	print_section(sbfd, "Sysname", ".uts_sysname");
	print_section(sbfd, "Machine", ".uts_machine");
	print_section(sbfd, "Release", ".uts_release");
	print_section(sbfd, "Version", ".uts_version");
	return 0;
}
