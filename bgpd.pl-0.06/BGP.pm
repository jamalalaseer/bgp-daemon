# BGP.pm - module implementating the BGP protocol (IETF RFC1771)
# Copyright (C) 2002 Steven Hessing 
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package BGP;

require Exporter;
@ISA = (Exporter);

use strict;
use warnings;

use POSIX qw(strftime);
use Socket;
use Sys::Hostname;
use Sys::Syslog qw(:DEFAULT setlogsock);
use FileHandle;

use BGP::Constants;
use BGP::Neighbor;
use BGP::PathAttribute;
use BGP::AdjRibIn;
use BGP::LocalRib;

sub new {
	my $this = shift;
	my $class = ref($this) || $this;

	my $self = {};
	bless $self, $class;

	my ($configfile, $logtype) = @_;

	$self->set_logging ($logtype);

	if (!$self->read_config_file($configfile)) {
		die "Unable to read $configfile: $!\n";
	}

	my $hostname = hostname();
	my ($name, $aliases, $type, $len, $clientaddr) = gethostbyname($hostname);

	die "unable to get my ip address in init_bgp_socket()" if ($name eq '');

	$$self{filehandle} = new FileHandle;

	my $proto = getprotobyname ('tcp');
	socket($$self{filehandle},AF_INET,SOCK_STREAM,$proto) || die "socket: $!";

	my $port = getservbyname ('bgp','tcp');
	my $sin = sockaddr_in($port, INADDR_ANY);
	setsockopt($$self{filehandle}, SOL_SOCKET, SO_REUSEADDR, pack ('l', 1));

	bind($$self{filehandle},$sin)                    || die "bind: $!";
	listen($$self{filehandle},5)                     || die "listen: $!";

	if (!defined $self->get_routerid ()) {
		$self->set_routerid ($clientaddr);
	}

	$$self{adjRIBin} = new BGP::AdjRibIn;
	$$self{localRIB} = new BGP::LocalRib;

	return $self;
}

sub DESTROY {
	my $bgprouter = shift;

	my $key;
	foreach $key ($bgprouter->get_established_neighbors ()) {
		my $neighbor = $bgprouter->get_neighbor ($key);
		$neighbor->close ($bgprouter->get_adjRIBin(), BGP_ERRC_Cease);
	}
}

sub incoming_connection {
	my $bgprouter = shift;

	my $from;
	my $tmpfh = new FileHandle;
	if (!($from=accept($tmpfh,$bgprouter->get_filehandle()))) {
		$bgprouter->log (128, 1, "incoming_connection: Can't accept: $!");
		return 0;
	}
	my ($port,$host) = sockaddr_in($from);
	my $host_ip = inet_ntoa ($host);
	 if (!$bgprouter->neighbor_exists ($host_ip)) {
		 $bgprouter->log (128, 16, "Incoming BGP session from $host_ip rejected");
		return $host_ip;
	}
	my $mysockaddr = getsockname ($tmpfh);
	my ($myport, $myhost) = sockaddr_in ($mysockaddr);

	$bgprouter->log (128, 4, "Established BGP session with $host_ip:$port");
	my $neighbor = $bgprouter->get_neighbor ($host_ip);

	# Nexthop here is the IP address for which we received the connection
	# request. We bind to * so we don't know what IP address the neighbor
	# used. We use this IP address as nexthop address when we send eBGP
	$neighbor->set_nexthop ($myhost);

	# Init the rest of the session data
	$neighbor->set_ipaddress ($host_ip);
	$neighbor->set_state (BGP_NEIGHBOR_ACTIVE);
	$neighbor->set_filehandle ($tmpfh);
	$neighbor->clear_routesin ();
	$neighbor->clear_routesout ();
	$neighbor->clear_routescurrent ();
	$neighbor->clear_history ();
	$neighbor->set_time ();
	$neighbor->add_history ("BGP Transport connection open");
	
	return 0;
}

sub get_adjRIBin {
	my $bgprouter = shift;

	return $$bgprouter{adjRIBin};
}

sub get_localRIB {
	my $bgprouter = shift;

	return $$bgprouter{localRIB};
}

sub get_filehandle {
	my $bgprouter = shift;

	return $$bgprouter{filehandle};
}

sub set_filehandle {
	my $bgprouter = shift;
	my $fh = shift;

	return $$bgprouter{filehandle} = $fh;
}

sub neighbor_exists {
	my $bgprouter = shift;
	my $ip = shift;

	return $bgprouter->get_neighbor ($ip);
}

sub connection_exists {
	my $bgprouter = shift;
	my $ip = shift;

	my $neighbor = $bgprouter->get_neighbor ($ip);
	return defined $neighbor->get_filehandle();
}

sub get_neighbor {
	my $self = shift;
	my $ip = shift;

	return $$self{neighbor}{$ip};
}

sub add_neighbor {
	my $self = shift;
	my $ip = shift;

	return if (defined $$self{neighbor}{$ip});

	return $$self{neighbor}{$ip} = new BGP::Neighbor ($ip);
}

sub get_neighbors {
	my $bgprouter = shift;

	return (keys %{$$bgprouter{neighbor}});
}

sub get_established_neighbors {
	my $bgprouter = shift;

	my @neighbors;
	my $key;
	foreach $key (keys %{$$bgprouter{neighbor}}) {
		my $neighbor = $bgprouter->get_neighbor ($key);
		my $state = $neighbor->get_state ();
		if (defined $state && $state == BGP_NEIGHBOR_ESTABLISHED) {
			push @neighbors, $key;
		}
	}
	return (@neighbors);
}

sub get_connected_neighbors {
	my $bgprouter = shift;

	my @neighbors;
	my $key;
	foreach $key (keys %{$$bgprouter{neighbor}}) {
		my $neighbor = $bgprouter->get_neighbor ($key);
		if (defined $neighbor->get_filehandle ()) {
			push @neighbors, $key;
		}
	}
	return (@neighbors);
}

sub get_routerid {
	my $bgprouter = shift;

	return $$bgprouter{ip};
}

sub set_routerid {
	my $bgprouter = shift;
	my $ip = shift;

	return $$bgprouter{ip} = $ip;
}

sub get_as {
	my $bgprouter = shift;

	return $$bgprouter{as};
}

sub set_as {
	my $bgprouter = shift;
	my $as = shift;

	return $$bgprouter{as} = $as;
}

sub read_config_file {
	my $bgprouter = shift;
	my ($file) = @_;

	my %bgp_log_types = (
		"OPEN" => 1,
		"UPDATE" => 2,
		"NOTIFICATION" => 4,
		"KEEPALIVE" => 8,
		"ROUTE-REFRESH" => 16,
		"LIST" => 32,
		"HEADER" => 64,
		"GENERAL" => 128,
		"LOCALRIB" => 256
	);

	my %bgp_log_levels = (
		"CRITICAL" => 1,
		"WARNING" => 2,
		"INFO" => 4,
		"PARSE" => 8,
		"SESSION-ERRORS" => 16,
		"SESSION-WARNINGS" => 32,
		"PARSE-OPEN" => 64,
		"PARSE-OPEN-OPTIONAL" => 128,
		"PARSE-UPDATE" => 64,
		"PARSE-UPDATE-PREFIX" => 128,
		"PARSE-UPDATE-PATH-ATTRIBUTRES" => 256,
		"PARSE-NOTIFICATION" => 64,
		"PARSE-REFRESH" => 64,
		"SESSION-PARSE" => 64,
		"LOCALRIB-CHANGES" => 64,
		"LOCALRIB-CHANGES-ROUTES" => 128,
		"LOCALRIB-CHANGES-EVAL" => 256
	);

	my $fh = new FileHandle;
	if (!open ($fh, $file)) {
		die "Error opening file $file: $!";
	}
	my $line;
	while ($line = get_config_line ($fh)) {
		$line = lc ($line);
		my @words = split /\s+/, $line;

		if ($words[0] eq "log") {
			my $type = uc ($words[1]);
			my $level = uc ($words[2]);
			if (defined $bgp_log_types{$type} &&
					defined $bgp_log_levels{$level} ) {
				$bgprouter->set_loglevel ($bgp_log_types{$type},
					$bgp_log_levels{$level});
			}
		}
		if ($words[0] eq "router" && $words[1] eq "bgp") {
			$bgprouter->set_as ($words[2]);
		}
		if ($words[0] eq "router-id") {
			$bgprouter->set_routerid (inet_aton($words[1]));
		}
		if ($words[0] eq "neighbor") {
			my $ip = $words[1];
			my $neighbor = $bgprouter->get_neighbor ($ip);
			if (!defined $neighbor) {
				$neighbor = $bgprouter->add_neighbor ($ip);
				$neighbor->set_ipaddress ($ip);
				$neighbor->set_log_filehandle
					($bgprouter->get_log_filehandle ());
				foreach my $type ($bgprouter->get_defined_loglevels ()) {
					my $level = $bgprouter->get_loglevel ($type);
					if (defined $level) {
						$neighbor ->set_loglevel ($type, $level);
					}
				}
			}
			if ($words[2] eq "remote-as") {
				my $as = $words[3];
				$neighbor->set_as ($as);
			}
		}
	}
	close $fh;
	return 1;
}

sub get_config_line {
	my ($fh) = @_;

	my $line = "";
	while ($line .= <$fh>) {
		# Remove whitespace at the beginning
		if ($line =~ /^\s+(.*)$/) {
			$line = $1;
		}
		# Remove comments
		if ($line =~ /^\s*(.*?)#.*$/) {
			$line = $1;
		}
		# Read next line if this one ends with the continuation char: \
		if ($line =~ /^\s*(\S.*)\\\s*$/) {
			$line = "$1 ";
			next;
		}
		# if line is empty then skip it
		if ($line =~ /^\w*$/) {
			$line = ""; next;
		}
		my $logm = $line; chop ($logm);
		return $line;
	}
	return undef;
}

sub process_keepalives {
	my $bgprouter = shift;

	# Send out keepalives and calculate time until we need to do it again.
	my $sleep_time = $bgprouter->process_keepalives_out ();
	# Have all our neighbors sent in their keepalives on time?
	$bgprouter->process_keepalives_in ();

	return $sleep_time;
}

sub setup_select {
	my $bgprouter = shift;

	my $rin = '';
	vec($rin,fileno($bgprouter->get_filehandle()),1) = 1;
	my $key;
	foreach $key ($bgprouter->get_connected_neighbors ()) {
		my $neighbor = $bgprouter->get_neighbor ($key);
		vec($rin, fileno($neighbor->get_filehandle()),1) = 1;
	}
	return $rin;
}

sub process_select {
	my $bgprouter = shift;
	my $rout = shift;

	my $count = 0;

	if (vec($rout,fileno($bgprouter->get_filehandle()),1)) {
		# We have a new incoming TCP connection.
		$bgprouter->incoming_connection();
		$count++;
	}
	my $key;
	foreach $key ($bgprouter->get_connected_neighbors ()) {
		my $neighbor = $bgprouter->get_neighbor ($key);
		$bgprouter->log (128, 4, "Processing input for: $key");
		if (vec ($rout, fileno ($neighbor->get_filehandle()) ,1) ) {
			# here we receive all BGP messages and maintain
			# $$bgprouter{adjRIBin}{ip}}, {removed} and {todo}
			# TODO: it is ugly that we send the bgprouter object
			my ($errorcode, $errorsubcode, $errordata) = 
				$neighbor->receive ($bgprouter);
			$count++;
			if ($errorcode) {
				$neighbor->close ($bgprouter->get_adjRIBin(), $errorcode,
					$errorsubcode, $errordata);
			}
		}
	}
	return $count;
}

sub maintain_RIBs {
	my $bgprouter = shift;

	my $localRIB = $bgprouter->get_localRIB ();
	$localRIB->maintain ($bgprouter);
	# adjRIBin doesn't need to be maintained here
	# adjRIBout still needs to be written
}

# dump_routingtable
# The routing table is currently implemented using hashes. This will be
# -very- slow for large routing tables. But the Tree::Radix implementation
# under http://www.linnaean.org/~hag/perl/radix/radix.html has not been
# released yet. We'll also need to look at
# http://www.nada.kth.se/~snilsson/public/code/router/ which describes an
# algoritm implemented in C or java that may be faster but which needs to
# be ported to perl5.

sub dump_routingtable {
	my $bgprouter = shift;

	my $adjRIBin = $bgprouter->get_adjRIBin();
	my $localRIB = $bgprouter->get_localRIB();

	my @origin = ('i', 'e', '?');

	my ($prefix_n, $len);
	foreach $prefix_n ($adjRIBin->get_prefixes()) {
		foreach $len (sort {$b <=> $a}
				$adjRIBin->get_prefix_lengths($prefix_n)) {
			my ($nexthop_n, $bestneighbor_n, $bestprefix_n, $bestlen) =
				$localRIB->lookup_route ($prefix_n, $len);
			if (!defined $nexthop_n) {
				$bgprouter->log (256,1,"No route in local-RIB for",
				inet_ntoa($prefix_n), "/$len");
				next;
			} 
			my $neighbor_n; 
			foreach $neighbor_n ($adjRIBin->get_neighbors ($prefix_n, $len)) {
				if ($neighbor_n eq $bestneighbor_n &&
						$prefix_n eq $bestprefix_n &&
						$len == $bestlen) {
					$bgprouter->lograw ("*");
				} else {
					$bgprouter->lograw (" ");
				}
				my $pa = $adjRIBin->get_pathattribute
					($prefix_n, $len, $neighbor_n);
				my $origin = $pa->get_origin ();
				my $nexthop = inet_ntoa ($pa->get_nexthop());
				my $local_pref = $pa->get_localpref ();
				my $med = $pa->get_med ();

				$bgprouter->lograw (sprintf 
					"%1s %15s/%-2s %15s %8s %8s", $origin[$origin],
					inet_ntoa ($prefix_n), $len, $nexthop,
					defined $local_pref ?  $local_pref : "undef",
					defined $med ?  $med : "undef");
				my @aspath = $pa->get_aspath ();
				my $aspath;
				foreach $aspath (@aspath) {
					$bgprouter->lograw (
						" (" . BGP_AS_PATH->[$pa->get_pathtype($aspath)].")");
					my @aslist = $pa->get_aslist ($aspath);
					my $as;
					foreach $as (@aslist) {
						$bgprouter->lograw (" $as");
					}
				}
				$bgprouter-> lograw (" ");
				my @comms = $pa->get_communities ();
				my $comm;
				foreach $comm (@comms) {
					my $up = $comm >> 16;
					my $low = $comm & 0xFFFF;
					$bgprouter->lograw ("$up:$low ");
				}
				$bgprouter->lograw ("\n");
			}
		}
	}
}

sub dump_neighbors {
	my $bgprouter = shift;

	my $key;
	foreach $key ($bgprouter->get_neighbors ()) {
		my $neighbor = $bgprouter->get_neighbor ($key);

		my $peer_ip = $neighbor->get_ipaddress ();
		my $as = $neighbor->get_as ();
		my $rin = $neighbor->get_routesin ();
		my $rout = $neighbor->get_routesout ();
		my $rcur = $neighbor->get_routescurrent ();
		my $rib = $neighbor->get_localRIBentries ();
		my $state = $neighbor->get_state ();
		my $t = $neighbor->get_time ();
		if (defined $t) {
			$t = strftime ("%D %T", localtime ($t));
		} else {
			$t = "never";
		}

		$bgprouter->lograw (sprintf
			"Neighbor %s AS: %d Status: %s (since %s)\n",
			$peer_ip, $as, BGP_NEIGHBOR_STATUS -> [$state], $t);
		$bgprouter->lograw (sprintf
			"Routes: %d recv, %d sent, %d cur, %d localRIB\n",
			$rin, $rout, $rcur, $rib);

		if ($state == BGP_NEIGHBOR_ESTABLISHED) {
			$bgprouter->lograw (sprintf
				"Holdtime: %3d Keepalive: %18s in, %18s out\n",
				$neighbor->get_holdtime (),
				strftime("%D %T",
				localtime($neighbor->get_timer_keepalivein ())),
				strftime("%D %T",
				localtime($neighbor->get_timer_keepaliveout ())));
		}
		my $hist;
		foreach $hist ($neighbor->get_history()) {
		my ($ti, $event) = $neighbor->get_history_detail ($hist);
			$bgprouter->lograw (sprintf "Event at %18s -> %s\n",
				strftime ("%D %T", localtime ($ti)), $event);
		}
	}
}

sub process_keepalives_out {
	my $bgprouter = shift;

	my $adjRIBin = $bgprouter->get_adjRIBin ();

	my $sleep_time = 180;
	my $now = time();

	my $key;
	foreach $key ($bgprouter->get_established_neighbors ()) {
		my $neighbor = $bgprouter->get_neighbor ($key);

		my $keepalive_out = $neighbor->get_timer_keepaliveout ();
		my $holdtime = $neighbor->get_holdtime ();
		if (defined $keepalive_out && defined $holdtime && $holdtime > 0) {
			my $next_keepalive_out = $keepalive_out + ($holdtime / 3) - $now;
			if ($next_keepalive_out <= 3) {
				if (!$neighbor->send_keepalive()) {
					$bgprouter->log (8, 16,
						"Can't send keepalive to $key: $!");
					$neighbor->close ($adjRIBin, -1);
				}
				$next_keepalive_out = $holdtime / 3;
			}
			if ($next_keepalive_out < $sleep_time) {
				$sleep_time = $next_keepalive_out;
			}
		}
	}
	return $sleep_time;
}

sub process_keepalives_in {
	my $bgprouter = shift;

	my $adjRIBin = $bgprouter->get_adjRIBin ();

	my $now = time();
	my $expired_count = 0;
	my $key;
	foreach $key ($bgprouter->get_established_neighbors ()) {
		my $neighbor = $bgprouter->get_neighbor ($key);

		my $keepalive_in = $neighbor->get_timer_keepalivein ();
		my $holdtime = $neighbor->get_holdtime ();

		if (defined $keepalive_in && defined $holdtime && $holdtime > 0) {
			if ($keepalive_in + $holdtime < $now) {
				$expired_count++;
				$bgprouter->log (8, 16, "Holdtimer expired for $key");
				$neighbor->close ($adjRIBin, BGP_ERRC_Hold_Timer_Expired);
			}
		}
	}
	return $expired_count;
}

sub set_loglevel {
	my $bgprouter = shift;
	
	my ($type, $level) = @_;

	$$bgprouter{log}{$type} = $level;
}
	
sub get_loglevel {
	my $bgprouter = shift;

	my $type = shift;

	return $$bgprouter{log}{$type};
}

sub get_defined_loglevels {
	my $bgprouter = shift;

	return (keys %{$$bgprouter{log}});
}

sub set_logging {
	my $bgprouter = shift;

	my ($logtype) = @_;

	$logtype = lc ($logtype);

	setlogsock ('unix');
	if ($logtype eq 'syslog') {
		openlog ('bgpd.pl', 'pid', 'daemon');
		$bgprouter->set_log_filehandle (undef);
	}
	if ($logtype eq 'file') {
		my $fh = new FileHandle;
		open ($fh, ">>bgpd.log");
		$bgprouter->set_log_filehandle ($fh);
	}
	if ($logtype eq 'stdout') {
		$bgprouter->set_log_filehandle (\*STDOUT);
	}
}

sub set_log_filehandle {
	my $bgprouter = shift;

	my $fh = shift;

	if (defined $fh) {
		$fh->autoflush ();
	}
	return $$bgprouter{loghandle} = $fh;
}


sub get_log_filehandle {
	my $bgprouter = shift;

	return $$bgprouter{loghandle};
}

sub log {
	my $bgprouter = shift;

	my ($type, $priority, @msgs) = @_;

	my $fh = $bgprouter->get_log_filehandle ();

	return if (!defined $fh && $priority > 2);

	my $loglevel = $bgprouter->get_loglevel ($type);

	if ($priority <= 2 || (defined ($loglevel) && $priority <= $loglevel) ) {
		my $message = "";
		if (defined $fh) {
			$message = strftime ("%D %T", localtime (time));
		}
		$message .= sprintf(" %03s/%03s BGP: ", $type, $priority);

		my $level;
		if ($priority == 1 || $priority == 16) {
			$message .= "-ERROR- ";
			$level = 'crit';
		}
		if ($priority == 2 || $priority == 32) {
			$message .= "WARNING ";
			$level = 'warning';
		}
		$message .= join (' ', @msgs);

		if (!defined $fh) {
			syslog ($level, $message);
		} else {
			print $fh "$message\n";
		}
	}
}

sub lograw {
	my $bgprouter = shift;

	my ($message) = @_;
	
	my $fh = $bgprouter->get_log_filehandle ();

	if (!defined $fh) {
		syslog ("info", $message);
	} else {
		print $fh $message;
	}
}
