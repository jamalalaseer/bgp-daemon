#!/usr/bin/perl -wT
use strict;
use local::lib;
use local::lib '/usr/local/lib/perl/5.18.2/';
$|=1;

# $Id: traceiface.pl,v 1.1 2007/02/04 22:58:04 jtk Exp $

# traceiface - traceroute with extension to discover router egress hop address

# TODO: IPv6 support

use Net::Traceroute::PurePerl;
use NetAddr::IP;
use Getopt::Std;
use Socket;

use constant PROGRAM_NAME => 'traceiface';

# gather parameters and validate them
my %opts = ();
getopts('d:f:i:m:M:np:P:q:s:w:', \%opts);

# expect at least a host argument, optional packet_size argument
usage() if ($#ARGV+1 < 1 || $#ARGV+1 > 3);
my $host = $ARGV[0];

# if it looks like a domain name, resolve it
my $domain_name;
if ($host !~ /^\d{1,3}(?:\.\d{1,3}){3}4/) {
    $domain_name = $host;
    my $packed_address = gethostbyname($domain_name) ||
        die PROGRAM_NAME, ": unknown host $host\n";
    # WARNING: using the first address we get
    $host = inet_ntoa($packed_address);
} 

my $packet_size;
$packet_size = $ARGV[1] if $#ARGV+1 == 2;
if ($packet_size) {
    usage() if ($packet_size < 0 || $packet_size > 65535);
}

my $debuglvl = $opts{d} || 0;
usage() if ($debuglvl < 0 || $debuglvl > 9);

my $first_ttl = $opts{f} || 1;
usage() if ($first_ttl < 0 || $first_ttl > 255);

my $interface = $opts{i} || undef;

my $max_ttl = $opts{m} || 32;
if ($max_ttl) { usage() if $max_ttl <= $first_ttl; }

# TODO: support IPv6 masks?
my $mask = $opts{M} || 24;
usage() if ($mask < 0 || $mask > 32);

my $name_resolution = 1 if $opts{n} || undef;

# PurePerl limits port selection to 1 to 65280 inclusive (no wrap)
my $base_port = $opts{p} || 33434;
usage() if ($base_port < 1 || $base_port > 65280);

# limited to what PurePerl module supports
# WARNING: PurePerl.pm has insecure dependency with UDP, this won't work
# TODO: fix PurePerl so UDP will work
use constant VALID_PROTOCOLS => 'icmp|udp';
my $protocol = lc($opts{P}) || 'icmp';
usage() if VALID_PROTOCOLS !~ /$protocol/;

my $nqueries = $opts{q} || 1;
usage() if ($nqueries < 1 || $nqueries > 65535);

#TODO: src_addr integrity check necessary?
my $src_addr = $opts{s} || undef;

my $wait_time = $opts{w} || 5;
usage() if ($wait_time < 1 || $wait_time > 65535);

# initialize traceroute object (host, first_hop and max_ttl set later)
my $t = new Net::Traceroute::PurePerl(
     debug => $debuglvl,
     device => $interface,
     base_port => $base_port,
     protocol => $protocol,
     queries => $nqueries,
     source_address => $src_addr,
     query_timeout => $wait_time,
     concurrent_hops => 1,
     packetlen => $packet_size,
);

# TODO: print summary line of trace to be performed

# main routine.  process each forward and backward hop
my $complete = 0;
for(my $hop = $first_ttl; $hop < $max_ttl; $hop++) {
    my $result;

    # the forward facing (probe ingress) interface
    $result = forward_trace($hop);
    print_hop($hop, 'forward');
    $complete = 1 if $result;

    # no backward facing interface on the first hop
    next if $hop == 1;

    # the backward facing (probe egress) interface
    $result = backward_trace($hop);
    if ($result) {
        print_hop($hop-1, 'backward');
    } else {
        printf "%s <  no backward hop found\n", $hop;
    }
    last if $complete;
}

#
# we have to post-process each hop so we set first_ttl and max_ttl to
# the current hop we receive from main.  this routine tries to get the
# forward ingress interface result for the hop we get from main.  we
# use the results later (available in the global var $t) in the
# backward_trace routine.  we also access the print_hop routine from
# here to display our results before returning our result to main.
#
sub forward_trace {
    my $hop = shift;

    # update per hop specific options
    $t->first_hop($hop);  # current hop
    $t->max_ttl($hop);    # current hop
    $t->host($host);      # user specified destination

    my $result = $t->traceroute();
    return $result;
}

#
# here is the novel addition to traceroute.  we attempt to find a response
# from a route hop one less than the last forward ingress response received.
# we do this by brute force, but somewhat intelligently guessing the backward
# facing neighbor address of the forward hop.  We reduce the TTL to one so
# that we know we got the backward facing router if we get an actual complete
# response as opposed to a TTL.  technically this could be another interface
# on the backward facing router, but we assume the first one we find in
# spreading range is the backward hop.
#
sub backward_trace {
    my $hop = shift;

    # TODO: how to examine all hosts that respond
    #       will hop_query_host($hop) return them all?
    #
    # return addr of the first host that responded
    my $forward_host = $t->hop_query_host($hop, 0) || return 0;

    # $mask is a global var
    my $backward_host = new NetAddr::IP "$forward_host/$mask";

    # TODO: verify this works and for /31's and /32's too
    # we loop out from addr as far as mask allows
    # we compute spreading range based on addresses in netblock
    # we add one because NetAddr::IP doesn't cont network/broacast addr
    # and we need to fan spread at least one for /31's and /32's
    my $range = round($backward_host->num() / 2) + 1;

    # try to find the neighbor address of the forward hop
    for (my $counter = 1; $counter < $range; $counter++) {
        my $host_to_test;

        # update traceroute object params
        $t->first_hop($hop-1);
        $t->max_ttl($hop-1);

        # first we decrement the address
        $host_to_test = $backward_host - $counter;
        $t->host($host_to_test->addr());
        my $result = $t->traceroute();
        return $result if $result;

        # now try incrementing the address 
        $host_to_test = $backward_host + $counter;
        $t->host($host_to_test->addr());
        $result = $t->traceroute();
        return $result if $result;
    }
    # no neighbor found
    return 0;
}

# print a line of output
#
sub print_hop {
    my $hop = shift;
    my $direction = shift;

    if ($direction eq 'forward') {
        printf '%d >  ', $hop;
    } else {
        # add one to align forward and backward output
        printf '%d <  ', $hop+1;
    }

    if (not $t->hop_queries($hop)) {
        print "error: no responses\n";
        return;
    }

    # loop through each of $nqueries
    for (my $query = 1; $query <= $t->hop_queries($hop); $query++) {
        my $host = $t->hop_query_host($hop, $query) || undef;

        # if we didn't get any response, move to the next  query
        if (not defined($host)) {
            print '* ';
            next;
        }
 
        # resolve names if applicable
        my $name;
        if ($name_resolution) {
            #TODO: create local cache?
            $name = gethostbyaddr(inet_aton($host), AF_INET) || undef;
        }
        if (defined $name) {
            printf '%-s  (%s)  ', $name, $host;
        } else {
            printf '%-s  ', $host;
        }

        my $time = $t->hop_query_time($hop, $query);
        if (defined $time && $time > 0) {
            printf '%7s ms ', $time;
        } else {
            print '* ';
        }
    }
    print "\n";
}

#
# from old Perl FAQ 4.13
sub round {
    my $number = shift;
    return int($number + .5 * ($number <=> 0));
}

#
# invalid invocation or help requested
#
sub usage {
    my $usage =
"Usage: traceiface [-n] [-d debuglvl] [-f first_ttl] [-i iface]
                    [-m max_ttl] [-P proto] [-p base_port] [-q nqueries]
                    [-s src_addr] [-w waittime] host [packetsize]\n";

   die $usage;
}
