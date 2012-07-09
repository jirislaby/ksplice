package Verbose;
use strict;
use warnings;

our $AUTOLOAD;
our $level = 0;

sub import {
	my $self = shift;
	my $minlevel = 0;
	foreach (@_) {
		if (m/^:(\d+)$/) {
			$minlevel = $1;
		} else {
			&make_verbose($minlevel, $_, (caller)[0]);
		}
	}
}

sub AUTOLOAD {
	&make_verbose($AUTOLOAD, (caller)[0]);
	goto &$AUTOLOAD;
}

sub debugcall {
	my ($minlevel, $name, @args) = @_;
	local $" = ', ';
	print "+ $name(@args)\n" if ($level >= $minlevel);
}

sub make_verbose {
	no strict 'refs';
	no warnings qw(redefine prototype);
	my ($minlevel, $sym, $pkg) = @_;
	$sym = "${pkg}::$sym" unless $sym =~ /::/;
	my $name = $sym;
	$name =~ s/.*::// or $name =~ s/^&//;
	my ($sref, $call, $proto);
	if (defined(&$sym)) {
		$sref = \&$sym;
		$call = '&$sref';
		$proto = prototype $sref;
	} else {
		$call = "CORE::$name";
		$proto = prototype $call;
	}
	$proto = '@' unless defined($proto);
	my $code = "package $pkg; sub ($proto) { Verbose::debugcall($minlevel, \"$name\", \@_); $call(\@_); }";
	*{$sym} = eval($code);
}

1;
