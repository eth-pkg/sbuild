#
# ChrootUnshare.pm: chroot library for sbuild
# Copyright © 2018      Johannes Schauer <josch@debian.org>
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

package Sbuild::ChrootUnshare;

use strict;
use warnings;

use English;
use File::Temp qw(mkdtemp);

# from sched.h
my $CLONE_NEWNS   = 0x20000;
my $CLONE_NEWUTS  = 0x4000000;
my $CLONE_NEWIPC  = 0x8000000;
my $CLONE_NEWUSER = 0x10000000;
my $CLONE_NEWPID  = 0x20000000;
my $CLONE_NEWNET  = 0x40000000;

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

sub _read_subuid_subgid() {
    my $username = getpwuid $<;
    my ($subid, $num_subid, $fh, $n);
    my @result = ();

    if (! -e "/etc/subuid") {
	printf STDERR "/etc/subuid doesn't exist\n";
	return;
    }
    if (! -r "/etc/subuid") {
	printf STDERR "/etc/subuid is not readable\n";
	return;
    }

    open $fh, "<", "/etc/subuid" or die "cannot open /etc/subuid for reading: $!";
    while (my $line = <$fh>) {
	($n, $subid, $num_subid) = split(/:/, $line, 3);
	last if ($n eq $username);
    }
    close $fh;
    push @result, ["u", 0, $subid, $num_subid];

    if (scalar(@result) < 1) {
	printf STDERR "/etc/subuid does not contain an entry for $username\n";
	return;
    }
    if (scalar(@result) > 1) {
	printf STDERR "/etc/subuid contains multiple entries for $username\n";
	return;
    }

    open $fh, "<", "/etc/subgid" or die "cannot open /etc/subgid for reading: $!";
    while (my $line = <$fh>) {
	($n, $subid, $num_subid) = split(/:/, $line, 3);
	last if ($n eq $username);
    }
    close $fh;
    push @result, ["g", 0, $subid, $num_subid];

    if (scalar(@result) < 2) {
	printf STDERR "/etc/subgid does not contain an entry for $username\n";
	return;
    }
    if (scalar(@result) > 2) {
	printf STDERR "/etc/subgid contains multiple entries for $username\n";
	return;
    }

    return @result;
}

sub _get_unshare_cmd {
    my $self = shift;
    my $options = shift;

    my @idmap = @{$self->{'Uid Gid Map'}};
    if (defined($options->{'IDMAP'})) {
	@idmap = @{$options->{'IDMAP'}};
    }

    my $unshare_flags = $CLONE_NEWUSER;

    if (defined($options->{'UNSHARE_FLAGS'})) {
	$unshare_flags |= $options->{'UNSHARE_FLAGS'};
    }

    my $uidmapcmd = "";
    my $gidmapcmd = "";
    foreach (@idmap) {
	my ($t, $hostid, $nsid, $range) = @{$_};
	if ($t ne "u" and $t ne "g" and $t ne "b") {
	    die "invalid idmap type: $t";
	}
	if ($t eq "u" or $t eq "b") {
	    $uidmapcmd .= " $hostid $nsid $range";
	}
	if ($t eq "g" or $t eq "b") {
	    $gidmapcmd .= " $hostid $nsid $range";
	}
    }
    my $idmapcmd = '';
    if ($uidmapcmd ne "") {
	$idmapcmd .= "0 == system \"newuidmap \$ppid $uidmapcmd\" or die \"newuidmap failed: \$!\";";
    }
    if ($gidmapcmd ne "") {
	$idmapcmd .= "0 == system \"newgidmap \$ppid $gidmapcmd\" or die \"newgidmap failed: \$!\";";
    }

    my $command = <<"EOF";
require 'syscall.ph';

# Create a pipe for the parent process to signal the child process that it is
# done with calling unshare() so that the child can go ahead setting up
# uid_map and gid_map.
pipe my \$rfh, my \$wfh;

# We have to do this dance with forking a process and then modifying the
# parent from the child because:
#  - new[ug]idmap can only be called on a process id after that process has
#    unshared the user namespace
#  - a process looses its capabilities if it performs an execve() with nonzero
#    user ids see the capabilities(7) man page for details.
#  - a process that unshared the user namespace by default does not have the
#    privileges to call new[ug]idmap on itself
#
# this also works the other way around (the child setting up a user namespace
# and being modified from the parent) but that way, the parent would have to
# stay around until the child exited (so a pid would be wasted). Additionally,
# that variant would require an additional pipe to let the parent signal the
# child that it is done with calling new[ug]idmap. The way it is done here,
# this signaling can instead be done by wait()-ing for the exit of the child.
my \$ppid = \$\$;
my \$cpid = fork() // die "fork() failed: \$!";
if (\$cpid == 0) {
	# child

	# Close the writing descriptor at our end of the pipe so that we see EOF
	# when parent closes its descriptor.
	close \$wfh;

	# Wait for the parent process to finish its unshare() call by waiting for
	# an EOF.
	0 == sysread \$rfh, my \$c, 1 or die "read() did not receive EOF";

	# The program's new[ug]idmap have to be used because they are setuid root.
	# These privileges are needed to map the ids from /etc/sub[ug]id to the
	# user namespace set up by the parent. Without these privileges, only the
	# id of the user itself can be mapped into the new namespace.
	#
	# Since new[ug]idmap is setuid root we also don't need to write "deny" to
	# /proc/\$\$/setgroups beforehand (this is otherwise required for
	# unprivileged processes trying to write to /proc/\$\$/gid_map since kernel
	# version 3.19 for security reasons) and therefore the parent process
	# keeps its ability to change its own group here.
	#
	# Since /proc/\$ppid/[ug]id_map can only be written to once, respectively,
	# instead of making multiple calls to new[ug]idmap, we assemble a command
	# line that makes one call each.
	$idmapcmd
	exit 0;
}

# parent

# After fork()-ing, the parent immediately calls unshare...
0 == syscall &SYS_unshare, $unshare_flags or die "unshare() failed: \$!";

# .. and then signals the child process that we are done with the unshare()
# call by sending an EOF.
close \$wfh;

# Wait for the child process to finish its setup by waiting for its exit.
\$cpid == waitpid \$cpid, 0 or die "waitpid() failed: \$!";
if (\$? != 0) {
	die "child had a non-zero exit status: \$?";
}

# Currently we are nobody (uid and gid are 65534). So we become root user and
# group instead.
#
# We are using direct syscalls instead of setting \$(, \$), \$< and \$> because
# then perl would do additional stuff which we don't need or want here, like
# checking /proc/sys/kernel/ngroups_max (which might not exist). It would also
# also call setgroups() in a way that makes the root user be part of the
# group unknown.
0 == syscall &SYS_setgid, 0 or die "setgid failed: \$!";
0 == syscall &SYS_setuid, 0 or die "setuid failed: \$!";
0 == syscall &SYS_setgroups, 0, 0 or die "setgroups failed: \$!";
EOF

    if ($options->{'FORK'}) {
	$command .= <<"EOF"
# When the pid namespace is also unshared, then processes expect a master pid
# to always be alive within the namespace. To achieve this, we fork() here
# instead of exec() to always have one dummy process running as pid 1 inside
# the namespace. This is also what the unshare tool does when used with the
# --fork option.
#
# Otherwise, without a pid 1, new processes cannot be forked anymore after pid
# 1 finished.
my \$cpid = fork() // die "fork() failed: \$!";
if (\$cpid != 0) {
    # The parent process will stay alive as pid 1 in this namespace until
    # the child finishes executing. This is important because pid 1 must
    # never die or otherwise nothing new can be forked.
    \$cpid == waitpid \$cpid, 0 or die "waitpid() failed: \$!";
    exit (\$? >> 8);
}
EOF
    }

    $command .= 'exec { $ARGV[0] } @ARGV or die "exec() failed: $!";';
    # remove code comments
    $command =~ s/^\s*#.*$//gm;
    # remove whitespace at beginning and end
    $command =~ s/^\s+//gm;
    $command =~ s/\s+$//gm;
    # remove linebreaks
    $command =~ s/\n//gm;
    return ('perl', '-e', $command);
}

sub begin_session {
    my $self = shift;

    my @idmap = $self->_read_subuid_subgid;

    # sanity check
    if (scalar(@idmap) != 2 || $idmap[0][0] ne 'u' || $idmap[1][0] ne 'g') {
	printf STDERR "invalid idmap\n";
	return 0;
    }

    $self->set('Uid Gid Map', \@idmap);

    my @cmd;
    my $exit;

    my @unshare_cmd = $self->_get_unshare_cmd;

    my $rootdir = mkdtemp($self->get_conf('UNSHARE_TMPDIR_TEMPLATE'));

    # $REAL_GROUP_ID is a space separated list of all groups the current user
    # is in with the first group being the result of getgid(). We reduce the
    # list to the first group by forcing it to be numeric
    my $outer_gid = $REAL_GROUP_ID+0;
    @cmd = ($self->_get_unshare_cmd({
		IDMAP => [['u', '0', $REAL_USER_ID, '1'],
		    ['g', '0', $outer_gid, '1'],
		    ['u', '1', $idmap[0][2], '1'],
		    ['g', '1', $idmap[1][2], '1'],
		]
	    }), 'chown', '1:1', $rootdir);
    if ($self->get_conf('DEBUG')) {
	printf STDERR "running @cmd\n";
    }
    system(@cmd);
    $exit = $? >> 8;
    if ($exit) {
	print STDERR "bad exit status ($exit): @cmd\n";
	return 0;
    }

    my $tarball = $self->get_conf('UNSHARE_TARBALL');

    if (! -e $tarball) {
	print STDERR "$tarball does not exist, check \$unshare_tarball config option\n";
	return 0;
    }

    if (! -r $tarball) {
	print STDERR "$tarball is not readable\n";
	return 0;
    }

    print STDOUT "Unpacking $tarball to $rootdir...\n";
    @cmd = (@unshare_cmd, 'tar',
	'--exclude=./dev/urandom',
	'--exclude=./dev/random',
	'--exclude=./dev/full',
	'--exclude=./dev/null',
	'--exclude=./dev/zero',
	'--exclude=./dev/tty',
	'--exclude=./dev/ptmx',
	'--directory', $rootdir,
	'--extract', '--file', $tarball
    );
    if ($self->get_conf('DEBUG')) {
	printf STDERR "running @cmd\n";
    }
    system(@cmd);
    $exit = $? >> 8;
    if ($exit) {
	print STDERR "bad exit status ($exit): @cmd\n";
	return 0;
    }

    $self->set('Session ID', $rootdir);

    $self->set('Location', '/sbuild-unshare-dummy-location');

    $self->set('Session Purged', 1);

    return 0 if !$self->_setup_options();

    return 1;
}

sub end_session {
    my $self = shift;

    return if $self->get('Session ID') eq "";

    print STDERR "Cleaning up chroot (session id " . $self->get('Session ID') . ")\n"
    if $self->get_conf('DEBUG');

    # this looks like a recipe for disaster, but since we execute "rm -rf" with
    # lxc-usernsexec, we only have permission to delete the files that were
    # created with the fake root user
    my @cmd = ($self->_get_unshare_cmd, 'rm', '-rf', $self->get('Session ID'));
    if ($self->get_conf('DEBUG')) {
	printf STDERR "running @cmd\n";
    }
    system(@cmd);
    # we ignore the exit status, because the command will fail to remove the
    # unpack directory itself because of insufficient permissions

    if(!rmdir($self->get('Session ID'))) {
	print STDERR "unable to remove " . $self->get('Session ID') . "\n";
	$self->set('Session ID', "");
	return 0;
    }

    $self->set('Session ID', "");

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

    if (!defined($dir)) {
	$dir = '/';
    }

    my $enablelo = '';
    my $unshare = $CLONE_NEWNS | $CLONE_NEWPID | $CLONE_NEWUTS | $CLONE_NEWIPC;
    if (defined($options->{'DISABLE_NETWORK'}) && $options->{'DISABLE_NETWORK'}) {
	$unshare |= $CLONE_NEWNET;
	$enablelo = 'ip link set lo up;';
    }

    @cmdline = (
	'env', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
	$self->_get_unshare_cmd({UNSHARE_FLAGS => $unshare, FORK => 1}), 'sh', '-c', "
	rootdir=\"\$1\"; shift;
	user=\"\$1\"; shift;
	dir=\"\$1\"; shift;
	hostname sbuild;
	$enablelo
	mkdir -p \"\$rootdir/dev\";
	for f in null zero full random urandom tty; do
	    touch \"\$rootdir/dev/\$f\";
	    chmod -rwx \"\$rootdir/dev/\$f\";
	    mount -o bind \"/dev/\$f\" \"\$rootdir/dev/\$f\";
	done;
	mkdir -p \"\$rootdir/sys\";
	mount -o rbind /sys \"\$rootdir/sys\";
	mkdir -p \"\$rootdir/proc\";
	mount -t proc proc \"\$rootdir/proc\";
	exec /usr/sbin/chroot \"\$rootdir\" /sbin/runuser -u \"\$user\" -- sh -c \"cd \\\"\\\$1\\\" && shift && \\\"\\\$@\\\"\" -- \"\$dir\" \"\$@\";
	", '--', $self->get('Session ID'), $user, $dir
    );
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
