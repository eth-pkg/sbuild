# BuildDepSatisfier.pm: build library for sbuild
# Copyright © 2005      Ryan Murray <rmurray@debian.org>
# Copyright © 2005-2008 Roger Leigh <rleigh@debian.org>
# Copyright © 2008      Simon McVittie <smcv@debian.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
#######################################################################

package Sbuild::BuildDepSatisfierBase;

use strict;
use warnings;
use Errno qw(:POSIX);

use Dpkg::Deps;
use Sbuild::Base;
use Sbuild qw(isin debug);

BEGIN {
    use Exporter ();
    our (@ISA, @EXPORT);

    @ISA = qw(Exporter Sbuild::Base);

    @EXPORT = qw();
}

sub new {
    my $class = shift;
    my $builder = shift;

    my $self = $class->SUPER::new($builder->get('Config'));
    bless($self, $class);

    $self->set('Builder', $builder);
    $self->set('Changes', {});

    return $self;
}

sub uninstall_deps {
    my $self = shift;
    my $builder = $self->get('Builder');

    my( @pkgs, @instd, @rmvd );

    $builder->lock_file($builder->get('Session')->get('Install Lock'), 1);

    @pkgs = keys %{$self->get('Changes')->{'removed'}};
    debug("Reinstalling removed packages: @pkgs\n");
    $builder->log("Failed to reinstall removed packages!\n")
	if !$self->run_apt("-y", \@instd, \@rmvd, 'install', @pkgs);
    debug("Installed were: @instd\n");
    debug("Removed were: @rmvd\n");
    $self->unset_removed(@instd);
    $self->unset_installed(@rmvd);

    @pkgs = keys %{$self->get('Changes')->{'installed'}};
    debug("Removing installed packages: @pkgs\n");
    $builder->log("Failed to remove installed packages!\n")
	if !$self->run_apt("-y", \@instd, \@rmvd, 'remove', @pkgs);
    $self->unset_installed(@pkgs);

    $builder->unlock_file($builder->get('Session')->get('Install Lock'));
}


sub set_installed {
    my $self = shift;

    foreach (@_) {
	$self->get('Changes')->{'installed'}->{$_} = 1;
    }
    debug("Added to installed list: @_\n");
}

sub set_removed {
    my $self = shift;
    foreach (@_) {
	$self->get('Changes')->{'removed'}->{$_} = 1;
	if (exists $self->get('Changes')->{'installed'}->{$_}) {
	    delete $self->get('Changes')->{'installed'}->{$_};
	    $self->get('Changes')->{'auto-removed'}->{$_} = 1;
	    debug("Note: $_ was installed\n");
	}
    }
    debug("Added to removed list: @_\n");
}

sub unset_installed {
    my $self = shift;
    foreach (@_) {
	delete $self->get('Changes')->{'installed'}->{$_};
    }
    debug("Removed from installed list: @_\n");
}

sub unset_removed {
    my $self = shift;
    foreach (@_) {
	delete $self->get('Changes')->{'removed'}->{$_};
	if (exists $self->get('Changes')->{'auto-removed'}->{$_}) {
	    delete $self->get('Changes')->{'auto-removed'}->{$_};
	    $self->get('Changes')->{'installed'}->{$_} = 1;
	    debug("Note: revived $_ to installed list\n");
	}
    }
    debug("Removed from removed list: @_\n");
}

sub get_dpkg_status {
    my $self = shift;
    my $builder = $self->get('Builder');
    my @interest = @_;
    my %result;
    local( *STATUS );

    debug("Requesting dpkg status for packages: @interest\n");
    my $dpkg_status_file = $builder->{'Chroot Dir'} . '/var/lib/dpkg/status';
    if (!open( STATUS, '<', $dpkg_status_file)) {
	$builder->log("Can't open $dpkg_status_file: $!\n");
	return ();
    }
    local( $/ ) = "";
    while( <STATUS> ) {
	my( $pkg, $status, $version, $provides );
	/^Package:\s*(.*)\s*$/mi and $pkg = $1;
	/^Status:\s*(.*)\s*$/mi and $status = $1;
	/^Version:\s*(.*)\s*$/mi and $version = $1;
	/^Provides:\s*(.*)\s*$/mi and $provides = $1;
	if (!$pkg) {
	    $builder->log_error("parse error in $dpkg_status_file: no Package: field\n");
	    next;
	}
	if (defined($version)) {
	    debug("$pkg ($version) status: $status\n") if $self->get_conf('DEBUG') >= 2;
	} else {
	    debug("$pkg status: $status\n") if $self->get_conf('DEBUG') >= 2;
	}
	if (!$status) {
	    $builder->log_error("parse error in $dpkg_status_file: no Status: field for package $pkg\n");
	    next;
	}
	if ($status !~ /\sinstalled$/) {
	    $result{$pkg}->{'Installed'} = 0
		if !(exists($result{$pkg}) &&
		     $result{$pkg}->{'Version'} eq '~*=PROVIDED=*=');
	    next;
	}
	if (!defined $version || $version eq "") {
	    $builder->log_error("parse error in $dpkg_status_file: no Version: field for package $pkg\n");
	    next;
	}
	$result{$pkg} = { Installed => 1, Version => $version }
	    if (isin( $pkg, @interest ) || !@interest);
	if ($provides) {
	    foreach (split( /\s*,\s*/, $provides )) {
		$result{$_} = { Installed => 1, Version => '~*=PROVIDED=*=' }
		if isin( $_, @interest ) and (not exists($result{$_}) or
					      ($result{$_}->{'Installed'} == 0));
	    }
	}
    }
    close( STATUS );
    return \%result;
}

sub get_apt_policy {
    my $self = shift;
    my $builder = $self->get('Builder');
    my @interest = @_;
    my $package;
    my $ver;
    my %packages;

    my $pipe =
	$builder->get('Session')->pipe_apt_command(
	    { COMMAND => [$self->get_conf('APT_CACHE'), 'policy', @interest],
	      ENV => {'LC_ALL' => 'C'},
	      USER => $self->get_conf('USERNAME'),
	      PRIORITY => 0,
	      DIR => '/' }) || die 'Can\'t start ' . $self->get_conf('APT_CACHE') . ": $!\n";

    while(<$pipe>) {
	$package=$1 if /^([0-9a-z+.-]+):$/;
	$packages{$package}->{curversion}=$1 if /^ {2}Installed: ([0-9a-zA-Z-.:~+]*)$/;
	$packages{$package}->{defversion}=$1 if /^ {2}Candidate: ([0-9a-zA-Z-.:~+]*)$/;
	if (/^ (\*{3}| {3}) ([0-9a-zA-Z-.:~+]*) 0$/) {
	    $ver = "$2";
	    push @{$packages{$package}->{versions}}, $ver;
	}
	if (/^ {5} *(-?\d+) /) {
	    my $prio = $1;
	    if (!defined $packages{$package}->{priority}{$ver} ||
	        $packages{$package}->{priority}{$ver} < $prio) {
		$packages{$package}->{priority}{$ver} = $prio;
	    }
	}
    }
    close($pipe);
    # Resort by priority keeping current version order if priority is the same
    use sort "stable";
    foreach my $package (keys %packages) {
	my $p = $packages{$package};
	if (exists $p->{priority}) {
	    $p->{versions} = [ sort(
		{ -($p->{priority}{$a} <=> $p->{priority}{$b}) } @{$p->{versions}}
	    ) ];
	}
    }
    no sort "stable";
    die $self->get_conf('APT_CACHE') . " exit status $?\n" if $?;

    return \%packages;
}

sub dump_build_environment {
    my $self = shift;
    my $builder = $self->get('Builder');

    my $status = $self->get_dpkg_status();

    my $arch = $builder->get('Arch');
    my ($sysname, $nodename, $release, $version, $machine) = POSIX::uname();
    $builder->log("Kernel: $sysname $release $arch ($machine)\n");

    $builder->log("Toolchain package versions:");
    foreach my $name (sort keys %{$status}) {
        foreach my $regex (@{$self->get_conf('TOOLCHAIN_REGEX')}) {
	    if ($name =~ m,^$regex, && defined($status->{$name}->{'Version'})) {
		$builder->log(' ' . $name . '_' . $status->{$name}->{'Version'});
	    }
	}
    }
    $builder->log("\n");

    $builder->log("Package versions:");
    foreach my $name (sort keys %{$status}) {
	if (defined($status->{$name}->{'Version'})) {
	    $builder->log(' ' . $name . '_' . $status->{$name}->{'Version'});
	}
    }
    $builder->log("\n");

}

sub run_apt {
    my $self = shift;
    my $mode = shift;
    my $inst_ret = shift;
    my $rem_ret = shift;
    my $action = shift;
    my @packages = @_;
    my( $msgs, $status, $pkgs, $rpkgs );

    my $builder = $self->get('Builder');

    return 1 if !@packages;

    $msgs = "";
    # redirection of stdin from /dev/null so that conffile question
    # are treated as if RETURN was pressed.
    # dpkg since 1.4.1.18 issues an error on the conffile question if
    # it reads EOF -- hardwire the new --force-confold option to avoid
    # the questions.
    my $pipe =
	$builder->get('Session')->pipe_apt_command(
	{ COMMAND => [$builder->get_conf('APT_GET'), '--purge',
		      '-o', 'DPkg::Options::=--force-confold',
		      '-q', "$mode", $action, @packages],
	  ENV => {'DEBIAN_FRONTEND' => 'noninteractive'},
	  USER => 'root',
	  PRIORITY => 0,
	  DIR => '/' });
    if (!$pipe) {
	$builder->log("Can't open pipe to apt-get: $!\n");
	return 0;
    }

    while(<$pipe>) {
	$msgs .= $_;
	$builder->log($_) if $mode ne "-s" || debug($_);
    }
    close($pipe);
    $status = $?;

    $pkgs = $rpkgs = "";
    if ($msgs =~ /NEW packages will be installed:\n((^[ 	].*\n)*)/mi) {
	($pkgs = $1) =~ s/^[ 	]*((.|\n)*)\s*$/$1/m;
	$pkgs =~ s/\*//g;
    }
    if ($msgs =~ /packages will be REMOVED:\n((^[ 	].*\n)*)/mi) {
	($rpkgs = $1) =~ s/^[ 	]*((.|\n)*)\s*$/$1/m;
	$rpkgs =~ s/\*//g;
    }
    @$inst_ret = split( /\s+/, $pkgs );
    @$rem_ret = split( /\s+/, $rpkgs );

    $builder->log("apt-get failed.\n") if $status && $mode ne "-s";
    return $mode eq "-s" || $status == 0;
}

sub format_deps {
    my $self = shift;

    return join( ", ",
		 map { join( "|",
			     map { ($_->{'Neg'} ? "!" : "") .
				       $_->{'Package'} .
				       ($_->{'Rel'} ? " ($_->{'Rel'} $_->{'Version'})":"")}
			     scalar($_), @{$_->{'Alternatives'}}) } @_ );
}

1;
