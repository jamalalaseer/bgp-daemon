#!/usr/bin/perl -w
# cpan Sys::Syslog
# apt-get install libreadonly-perl
# apt-get install Net-CIDR-Lite*
# Net::CIDR::Lite
# Sys::Syslog
# cpanm Net::Patricia
# perl -MCPAN -e shell
# perl Makefile.PL
#  make
#  make test
#  make install
# bgpd.pl - limited functionality BGP daemon implementation.
# Copyright (C) 2002 Steven Hessing
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

use strict;
use local::lib;
use local::lib '/usr/local/lib/perl/5.18.2/';
use Sys::Syslog;
use Getopt::Long;

use BGP;

my $term_signal_received = 0;
my $hup_signal_received = 0;
my $usr1_signal_received = 0;
my $usr2_signal_received = 0;
 
{
	my ($daemon, $logtype, $configfile) = (1, "", "bgpd.conf");
	GetOptions ('daemon!' => \$daemon, 'log=s' => \$logtype,
		'config=s' => \$configfile);

	$daemon = 0 if ($logtype eq 'stdout');

	my $bgprouter = new BGP ($configfile, $logtype);

	daemonize() if ($daemon);

	syslog ('daemon|notice', "Starting bgpd.pl[$$]");

	# On SIGTERM, we close all BGP sessions and exit(1);
	$SIG{TERM} = \&process_term_signal;
	# On SIGUSR1, we provide a dump of the adj-RIB-in
	$SIG{USR1} = \&process_usr1_signal;
	# On SIGUSR2, we provide an overview of the BGP sessions with our neighbors
	$SIG{USR2} = \&process_usr2_signal;

	until ($term_signal_received) {
		if ($usr1_signal_received) {
			$usr1_signal_received = 0;
			$bgprouter->dump_routingtable ();
		}
		if ($usr2_signal_received) {
			$usr2_signal_received = 0;
			$bgprouter->dump_neighbors ();
		}

		# This processes incoming and outgoing BGP keepalive timers
		my $sleep_time = $bgprouter->process_keepalives ();

		# Set up the `select' statement.
		my $rout='';
		my $rin = $bgprouter->setup_select ();

		$bgprouter->log (128, 4, "Starting select ($sleep_time seconds)");
		my $nfound = select($rout=$rin,undef,undef,$sleep_time);
		$bgprouter->log (128, 4,"Exiting select: ($nfound sockets have input)");
		if ($nfound > 0) {
			$bgprouter->process_select ($rout);
	  	}
		$bgprouter->maintain_RIBs ();
	}
	syslog ('daemon|notice', "Exiting bgpd.pl[$$]");
}

# process_term_signal
#
# will be called by signal handler when a SIGTERM is received. This
# function should be as short as possible. It sets the global variable
# $term_signal_received.
# 
# input:
#	(none)
# output:
#	(none)
#
sub process_term_signal {
	$term_signal_received = 1;
	$SIG{TERM} = \&process_term_signal;
}

# process_hup_signal
#
# will be called by signal handler when a SIGHUP is received. This
# function should be as short as possible. It sets the global variable
# $hup_signal_received.
# 
# input:
#	(none)
# output:
#	(none)
#
sub process_hup_signal {
	$hup_signal_received = 1;
	$SIG{HUP} = \&process_hup_signal;
}

# process_usr1_signal
#
# will be called by signal handler when a SIGHUP is received. This
# function should be as short as possible. It sets the global variable
# $usr1_signal_received.
# 
# input:
#	(none)
# output:
#	(none)
#
sub process_usr1_signal {
	$usr1_signal_received = 1;
	$SIG{USR1} = \&process_usr1_signal;
}
# process_usr2_signal
#
# will be called by signal handler when a SIGHUP is received. This
# function should be as short as possible. It sets the global variable
# $usr2_signal_received.
# 
# input:
#	(none)
# output:
#	(none)
#
sub process_usr2_signal {
	$usr2_signal_received = 1;
	$SIG{USR2} = \&process_usr2_signal;
}

sub daemonize {
	# Make this process run as daemon
	# fork, chdir to '/' and detach from tty
	fork && exit;
	chdir "/";
	open (TTY, "+>/dev/tty") ||
		warn ("$0: Couldn't detach from controlling tty: $!");
	ioctl(TTY,0x20007471,0);
	close (TTY);
	close (STDIN);
	close (STDOUT);
	close (STDERR);
}

