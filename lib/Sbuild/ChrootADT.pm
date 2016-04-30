#
# Chroot.pm: chroot library for sbuild
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

package Sbuild::ChrootADT;

use strict;
use warnings;

use IPC::Open2;
use Sbuild qw(shellescape);

BEGIN {
    use Exporter ();
    use Sbuild::Chroot;
    our (@ISA, @EXPORT);

    @ISA = qw(Exporter Sbuild::Chroot);

    @EXPORT = qw();
}

sub new {
    my $class = shift;
    my $conf = shift;
    my $chroot_id = shift;

    my $self = $class->SUPER::new($conf, $chroot_id);
    bless($self, $class);

    return $self;
}

sub begin_session {
    my $self = shift;
    my $chroot = $self->get('Chroot ID');

    # Don't use namespaces in compat mode.
    if ($Sbuild::Sysconfig::compat_mode) {
	$chroot =~ s/^[^:]+://msx;
    }

    my ($chld_out, $chld_in);
    my $pid = open2(
	$chld_out, $chld_in,
	$self->get_conf('ADT_VIRT_SERVER'),
	@{$self->get_conf('ADT_VIRT_SERVER_OPTIONS')},
	$chroot);

    if (!$pid) {
	print STDERR "Chroot setup failed\n";
	return 0;
    }

    chomp (my $status = <$chld_out>);

    if (! defined $status || $status ne "ok") {
 	print STDERR "adt-virt server returned unexpected value: $status\n";
	kill 'KILL', $pid;
	return 0;
    }

    print $chld_in "open\n";

    chomp ($status = <$chld_out>);

    my $adt_session;
    if ($status =~ /^ok (.*)$/) {
	$adt_session = $1;
	$self->set('Session ID', $adt_session);
    } else {
	print STDERR "adt-virt server: cannot open: $status\n";
	kill 'KILL', $pid;
	return 0;
    }

    print STDERR "Setting up chroot $chroot (session id $adt_session)\n"
	if $self->get_conf('DEBUG');

    print $chld_in "capabilities\n";

    chomp ($status = <$chld_out>);

    my @capabilities;
    if ($status =~ /^ok (.*)$/) {
	@capabilities = split /\s+/, $1;
    } else {
	print STDERR "adt-virt server: cannot capabilities: $status\n";
	kill 'KILL', $pid;
	return 0;
    }

    if (! grep {$_ eq "root-on-testbed"} @capabilities) {
	print STDERR "adt-virt server: capability root-on-testbed missing\n";
	kill 'KILL', $pid;
	return 0;
    }

    # TODO: also test "revert" capability

    print $chld_in "print-execute-command\n";

    chomp ($status = <$chld_out>);

    my $exec_cmd;
    if ($status =~ /^ok (.*)$/) {
	$exec_cmd = $1;
    } else {
	print STDERR "adt-virt server: cannot print-execute-command: $status\n";
	kill 'KILL', $pid;
	return 0;
    }

    my @exec_args = split /,/, $exec_cmd;

    @exec_args = map { s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg; $_ } @exec_args;

    $self->set('Location', '/adt-virt-dummy-location');
    $self->set('ADT Pipe In', $chld_in);
    $self->set('ADT Pipe Out', $chld_out);
    $self->set('ADT Virt PID', $pid);
    $self->set('ADT Exec Command', \@exec_args);

    return 0 if !$self->_setup_options();

    return 1;
}

sub end_session {
    my $self = shift;

    return if $self->get('Session ID') eq "";

    print STDERR "Cleaning up chroot (session id " . $self->get('Session ID') . ")\n"
	if $self->get_conf('DEBUG');

    my $chld_in = $self->get('ADT Pipe In');
    my $chld_out = $self->get('ADT Pipe Out');
    my $pid = $self->get('ADT Virt PID');

    print $chld_in "close\n";

    chomp (my $status = <$chld_out>);

    if ($status ne "ok") {
 	print STDERR "adt-virt server: cannot close: $status\n";
	return 0;
    }

    print $chld_in "quit\n";

    waitpid $pid, 0;

    if ($?) {
	my $child_exit_status = $? >> 8;
	print STDERR "adt-virt quit with exit status $child_exit_status\n";
	return 0;
    }

    return 1;
}

sub get_command_internal {
    my $self = shift;
    my $options = shift;

    # Command to run. If I have a string, use it. Otherwise use the list-ref
    my $command = $options->{'INTCOMMAND_STR'} // $options->{'INTCOMMAND'};

    my $user = $options->{'USER'};          # User to run command under
    my $dir;                                # Directory to use (optional)
    $dir = $self->get('Defaults')->{'DIR'} if
	(defined($self->get('Defaults')) &&
	 defined($self->get('Defaults')->{'DIR'}));
    $dir = $options->{'DIR'} if
	defined($options->{'DIR'}) && $options->{'DIR'};

    if (!defined $user || $user eq "") {
	$user = $self->get_conf('USERNAME');
    }

    my @cmdline = ();

    @cmdline = @{$self->get('ADT Exec Command')};

    if ($user ne "root") {
	push @cmdline, "/sbin/runuser", '-u', $user, '--';
    }

    if (defined($dir)) {
	my $shelldir = shellescape $dir;
	push @cmdline, 'sh', '-c', "cd $shelldir && exec \"\$@\"", 'exec';
    } else {
	$dir = '/';
    }

    if (ref $command) {
        push @cmdline, @$command;
    } else {
        push @cmdline, ('/bin/sh', '-c', $command);
        $command = [split(/\s+/, $command)];
    }

    $options->{'USER'} = $user;
    $options->{'COMMAND'} = $command;
    $options->{'EXPCOMMAND'} = \@cmdline;
    $options->{'CHDIR'} = undef;
    $options->{'DIR'} = $dir;
}

1;
