#!/usr/bin/perl

# Copyright (C) 2008-2009  Ksplice, Inc.
# Authors: Anders Kaseorg, Jeff Arnold, Tim Abbott
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
# 02110-1301, USA.

use strict;
use warnings;
use IPC::Open3;
use Cwd qw(abs_path);
use File::Basename;

my $dir = abs_path(dirname($0) . "/ksplice-patch");
my @cmd;
foreach (@ARGV) {
	if (/^-ksplice-cflags-api=1$/) {
		push @cmd, "-I$dir";
		push @cmd, qw(-D__DATE__="<{DATE...}>" -D__TIME__="<{TIME}>");
	} else {
		push @cmd, $_;
	}
}

my $pid = open3('<&STDIN', '>&STDOUT', \*ERROR, @cmd);
while (<ERROR>) {
	next if /^<command[- ]line>(?::\d+:\d+)?: warning: "(?:__DATE__|__TIME__)" redefined$/;
	print STDERR;
}
close ERROR;
waitpid($pid, 0) == $pid and ($? & 127) == 0 or die;
exit($? >> 8);
