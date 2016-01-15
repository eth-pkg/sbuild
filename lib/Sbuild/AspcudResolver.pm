# ResolverBase.pm: build library for sbuild
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

package Sbuild::AspcudResolver;

use strict;
use warnings;

use Sbuild::Base;
use Sbuild::ResolverBase;

BEGIN {
    use Exporter ();
    our (@ISA, @EXPORT);

    @ISA = qw(Exporter Sbuild::ResolverBase);

    @EXPORT = qw();
}

sub new {
    my $class = shift;
    my $conf = shift;
    my $session = shift;
    my $host = shift;

    my $self = $class->SUPER::new($conf, $session, $host);
    bless($self, $class);

    return $self;
}

sub install_deps {
    my $self = shift;
    my $name = shift;
    my @pkgs = @_;

    my $status = 0;
    my $session = $self->get('Session');
    my $dummy_pkg_name = 'sbuild-build-depends-' . $name. '-dummy';

    # Call functions to setup an archive to install dummy package.
    $self->log_subsubsection("Setup apt archive");

    if (!$self->setup_apt_archive($dummy_pkg_name, @pkgs)) {
	$self->log_error("Setting up apt archive failed");
	return 0;
    }

    if (!$self->update_archive()) {
	$self->log_error("Updating apt archive failed");
	return 0;
    }

    $self->log_subsection("Install $name build dependencies (aspcud-based resolver)");
    #install aspcud first:
    my (@aspcud_installed_packages, @aspcud_removed_packages);
    if (!$self->run_apt('-y', \@aspcud_installed_packages, \@aspcud_removed_packages, 'install', 'apt-cudf', 'aspcud')) {
	$self->log_warning('Could not install aspcud!');
	goto cleanup;
    }
    $self->set_installed(@aspcud_installed_packages);
    $self->set_removed(@aspcud_removed_packages);

    # Install the dummy package
    my (@instd, @rmvd);
    $self->log("Installing build dependencies\n");
    my @apt_args = ("-yf", \@instd, \@rmvd);
    push @apt_args, 'install', $dummy_pkg_name;

    # It follows an explanation of the choice of the
    # APT::Solver::aspcud::Preferences setting
    #
    # Since it is assumed that the chroot only contains a base system and
    # build-essential, from which we assume that no package shall be removed,
    # we first minimize the number of removed packages. This means that if
    # there exist solutions that do not remove any packages, then those will
    # be evaluated further. The second optimization criteria is to minimize
    # the number of changed packages. This will take care that no packages of
    # the base system are unnecessarily upgraded to their versions from
    # experimental. It will also avoid any solutions that do need upgrades to
    # the experimental versions and keep the upgrades to a minimum if an
    # upgrade is strictly required. The third criteria minimizes the number of
    # new packages the solution installs. Here it can happen that installing a
    # dependency from experimental instead of unstable will lead to less new
    # packages. But this should only happen if the package in unstable depends
    # on more additional packages compared to the same package in
    # experimental. If the solutions are otherwise equal then as the last
    # criteria, the number of packages from experimental will be minimized by
    # maximizing the sum of the apt-pin values. Since packages from unstable
    # have a higher pin value than those in experimental, this should prefer
    # packages from unstable except if the solution from unstable is so large
    # compared to the one in experimental that their sum of pin values is
    # larger in which case the solution in experimental will be preferred.
    push @apt_args, '--solver',  'aspcud', '-o', 'APT::Solver::Strict-Pinning=false', '-o', 'APT::Solver::aspcud::Preferences=-removed,-changed,-new,+sum(solution,apt-pin)';

    if (!$self->run_apt(@apt_args)) {
	$self->log("Package installation failed\n");
	if (defined ($self->get('Session')->get('Session Purged')) &&
	    $self->get('Session')->get('Session Purged') == 1) {
	    $self->log("Not removing build depends: cloned chroot in use\n");
	} else {
	    $self->set_installed(@instd);
	    $self->set_removed(@rmvd);
	    goto package_cleanup;
	}
	return 0;
    }
    $self->set_installed(@instd);
    $self->set_removed(@rmvd);
    $status = 1;

  package_cleanup:
    if ($status == 0) {
	if (defined ($session->get('Session Purged')) &&
	    $session->get('Session Purged') == 1) {
	    $self->log("Not removing installed packages: cloned chroot in use\n");
	} else {
	    $self->uninstall_deps();
	}
    }

  cleanup:
    $self->cleanup_apt_archive();

    return $status;
}

1;
