# LocalRib.pm - BGP local-RIB forwarding table management
# Copyright (C) 2002 Steven Hessing 
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package BGP::LocalRib;
require Exporter;
@ISA = (Exporter);

use strict;
use warnings;

use Net::Patricia;
use Socket;

sub new {
	my $this = shift;
	my $class = ref($this) || $this;

	my $self = {};
	$$self{table} = new Net::Patricia;
	bless $self, $class;
	return $self;
}

sub maintain {
	my $localRIB = shift;
	my $bgprouter = shift;

	my $adjRIBin = $bgprouter->get_adjRIBin ();

	my $purgecount = $localRIB->purge ($bgprouter);

	my ($prefix_n, $len);

	# go through all todo routes in $prefix/$len order
	foreach $prefix_n ($adjRIBin->get_todo_prefixes()) {
		foreach $len ($adjRIBin->get_todo_prefix_lengths ($prefix_n)) {
			my $cidr_s = inet_ntoa ($prefix_n) . "/$len";
			$bgprouter->log (256, 128, "Doing $cidr_s");
			my ($current_nexthop_n, $current_neighbor_ip_n,
				$localRIBprefix_n, $localRIBlen) =
				$localRIB->lookup_route ($prefix_n, $len);

			my $best_neighbor_n;
			if (defined $current_neighbor_ip_n && $localRIBlen == $len &&
					$localRIBprefix_n eq $prefix_n) {
				if ($adjRIBin->prefix_exists ($prefix_n, $len,
						$current_neighbor_ip_n)) {
					$best_neighbor_n = $current_neighbor_ip_n;
					$bgprouter->log (256, 128, "Announcement for $cidr_s will",
						"potentially replace existing entry in local-RIB");
				} else {
					$bgprouter->log (256, 128, "Existing selected peer",  
						inet_ntoa($current_neighbor_ip_n), 
						"is no longer in adj-RIB-in");
				}
			}

			# All neighbors who have announced this route except possibly
			# the current neighbor in local-RIB. Their route
			# announcements are eligable to be chosen as best route.
			my @neighbors_n = ();
			if ($adjRIBin->prefix_exists ($prefix_n, $len)) {
				if (!defined $best_neighbor_n) {
					@neighbors_n = $adjRIBin->get_neighbors ($prefix_n, $len);
					$best_neighbor_n = shift @neighbors_n;
				} else {
					@neighbors_n = $adjRIBin->get_neighbors ($prefix_n, $len,
						$best_neighbor_n);
				}
			} else {
				if (defined $best_neighbor_n) {
					$bgprouter->log (256, 2, "Route $cidr_s is in",
						"local-RIB but not in adj-RIB-in");
					$localRIB->delete_route ($prefix_n, $len);
					my $neighbor = $bgprouter->get_neighbor
						(inet_ntoa ($current_neighbor_ip_n));
					$neighbor->decrease_localRIBentries ();
				} else {
					$bgprouter->log (256, 128, "$cidr_s will not be added to",
					"local-RIB because there are no candidates in adj-RIB-in");
				}
				next;
			}

			my $peercount = $#neighbors_n + 1;
			$bgprouter->log (256, 128, "Number of other routes in adj-RIB-in",
				"to be considered: $peercount");

			my $trypeer_n;
			foreach $trypeer_n (@neighbors_n) {
				my $trypeer_s = inet_ntoa ($trypeer_n);
				$bgprouter->log (256, 128, "Checking whether peer $trypeer_s",
					"has a better route then", inet_ntoa($best_neighbor_n));
				if (is_better_route ($prefix_n, $len, $adjRIBin, $bgprouter,
						$best_neighbor_n, $trypeer_n)) {
					$bgprouter->log (256, 128,
						"Yes, route of $trypeer_s is better");
					$best_neighbor_n = $trypeer_n;
				}
			}
			if (defined $current_neighbor_ip_n &&
					$best_neighbor_n eq $current_neighbor_ip_n &&
					$prefix_n eq $localRIBprefix_n && $len eq $localRIBlen) {
				# We do nothing because:
				# route in local-RIB is still the best of all
				# the best of all routes in adj-RIB-in
			} else {
				# Add or replace route in local-RIB
				my $pa = $adjRIBin->get_pathattribute ($prefix_n, $len,
					$best_neighbor_n);
				my $nexthop_n = $pa->get_nexthop();
				$localRIB->add_route ($prefix_n, $len, $nexthop_n,
					$best_neighbor_n);

				my $neighbor = $bgprouter->get_neighbor
					(inet_ntoa ($best_neighbor_n));
				$neighbor->increase_localRIBentries ();
				$bgprouter->log (256,128, "localRIBentries is now:",
					$neighbor->get_localRIBentries());
				my $nexthop_s = inet_ntoa ($nexthop_n);
				if (! defined $current_neighbor_ip_n || $len ne $localRIBlen ||
					$prefix_n ne $localRIBprefix_n) {
					$bgprouter->log (256,64, "Adding $cidr_s with",
						"next-hop $nexthop_s to local-RIB");
				} else {
					my $oldneighbor = $bgprouter->get_neighbor
						(inet_ntoa($current_neighbor_ip_n));
					$oldneighbor->decrease_localRIBentries();
					$bgprouter->log (256, 64, "Replacing $cidr_s",
						"with next-hop", inet_ntoa ($current_nexthop_n),
					 	"from", inet_ntoa ($current_neighbor_ip_n), 
						"with next-hop", inet_ntoa ($current_nexthop_n));
				}
			}
			$adjRIBin->delete_todo ($prefix_n, $len);
		}
		$adjRIBin->delete_todo ($prefix_n);
	}
}

sub is_better_route {
	my ($prefix, $len, $adjRIBin, $bgprouter, $curpeer, $trypeer) = @_;

	my $attr1 = $adjRIBin->get_pathattribute ($prefix, $len, $curpeer);
	my $attr2 = $adjRIBin->get_pathattribute ($prefix, $len, $trypeer);

	my $temp;

	# Rule 1: if nexthop is inaccessible do not consider it
	# -> We don't interact with any IGP so we assume it is always accessible

	# Rule 2: prefer the largest weigth
	# -> We don't maintain weigths, so ignore

	# Rule 3: prefer the largest Local Preference
	my ($lp1, $lp2) = (0,0);
	if (defined ($temp = $attr1->get_localpref ())) {
		$lp1 = $temp;
	}
	if (defined ($temp = $attr2->get_localpref ())) {
		$lp2 = $temp;
	}
	$bgprouter->log (256, 256, "local pref $lp1 vs. local pref $lp2");
	return 1 if ($lp1 < $lp2);

	# Rule 4: prefer the route that the specified router has originated
	# TODO: how do we know this?

	# Rule 5: If no route was originated prefer the shorter AS path
	my ($ascount1, $ascount2) = (0,0);
	my $aspath;
	foreach $aspath ($attr1->get_aspath ()) {
		$ascount1 += $attr1->get_aslist($aspath);
	}
	foreach $aspath ($attr2->get_aspath ()) {
		$ascount2 += $attr2->get_aslist ($aspath);
	}
	$bgprouter->log (256, 256, "AS path length $ascount1 vs.",
		"AS path length $ascount2");
	return 1 if ($ascount1 > $ascount2);

	# Rule 6: prefer the lowest origin code (IGP<EGP<INCOMPLETE).
	return 1 if ($attr1->get_origin () > $attr2->get_origin ());

	# Rule 7: prefer the path with the lowest MED
	my ($med1, $med2) = (0xFFFFFFFF, 0xFFFFFFFF);
	if (defined ($temp = $attr1->get_med () )) {
		$med1 = $temp;
	}
	if (defined ($temp = $attr2->get_med () )) {
		$med2 = $temp;
	}
	$bgprouter->log (256, 256, "MED $med1 vs MED $med2");
	return 1 if ($med1 > $med2);

	# Rule 8: Prefer closest IGP neighbor.
	# We don't do IGP

	# Rule 9:Prefer the route with the lowest ip address value for BGP router ID
	# TODO: we don't pass $peerref yet :-(
	$bgprouter->log (256, 256, "defaulting to true :-(");
	return 1;
}

sub purge {
	my $localRIB = shift;
	my $bgprouter = shift;

	my $adjRIBin = $bgprouter->get_adjRIBin ();

	my $purge_count = 0;
	my ($prefix, $len);

	# Go through all routes that have been withdrawn in BGP UPDATE messages
	# or which should be deleted because the BGP session with the announcing
	# neighbor is gone. Cycle through each $prefix/$len combo.
	foreach $prefix (keys %{$$adjRIBin{removed}{ip}}) {
		foreach $len (keys %{$$adjRIBin{removed}{ip}{$prefix}}) {

			my ($next_hop, $neighbor, $RIBprefix, $RIBlen) = 
				$localRIB->lookup_route ($prefix, $len);

			my $cidr = inet_ntoa ($prefix) . "/$len";

			# Is this withdrawn route in localRIB? If not then we send a warning
			# If yes then we have to delete if the announcing peer is the same
			if (defined $next_hop) {
				my $nexthop_s = inet_ntoa ($next_hop);
				my $neighbor_s = inet_ntoa ($neighbor);

				# If the withdrawing neighbor was the one who provided the
				# announcment in the first place then we delete it from
				# local-RIB here. The interesting case is where a peer
				# withdraws a route with a next-hop address not his own
				# while we also received the route with the same next-hop
				# address from another peer and installed that advertisement
				# in local-RIB. In that case we should keep the route in
				# local-RIB.
				if (defined $$adjRIBin{removed}{ip}{$prefix}{$len}{$neighbor}) {
					$purge_count++;
					$localRIB->delete_route ($prefix, $len);
					my $neighborobj = $bgprouter->get_neighbor ($neighbor);
					$neighborobj->decrease_localRIBentries();
					$bgprouter->log (256, 64, "Removing $cidr with",
						"next-hop $nexthop_s from local-RIB");
					# Do a route selection for this prefix
					$adjRIBin->add_todo ($prefix, $len);
				} else {
					$bgprouter->log (256, 128, "$cidr from $neighbor_s",
					"never made it to local-RIB");
				}
			} else {
				my $peer;
				foreach $peer (keys %{$$adjRIBin{removed}{ip}{$prefix}{$len}}) {
					$bgprouter->log (256, 32, "Trying to delete route $cidr",
						"which doesn't exist in local-RIB");
				}
			}
			delete $$adjRIBin{removed}{ip}{$prefix}{$len};
		}
		delete $$adjRIBin{removed}{ip}{$prefix};
	}
	return $purge_count;
}

sub add_route {
	my $localRIB = shift;
	my ($prefix, $len, $nexthop, $neighbor) = @_;

	if (length ($prefix) == 4) {
		$prefix = inet_ntoa ($prefix);
	}
	my $data = inet_aton ($prefix) . pack ("C", $len) . $nexthop . $neighbor;
	my $table = $$localRIB{table};
	$table->add_string ("$prefix/$len", \$data);
}

sub delete_route {
	my $localRIB = shift;
	my ($prefix, $len) = @_;

	if (length ($prefix) == 4) {
		$prefix = inet_ntoa ($prefix);
	}
	my $table = $$localRIB{table};
	$table->remove_string ("$prefix/$len");
}

sub lookup_route {
	my $localRIB = shift;
	my ($prefix, $len) = @_;

	my $table = $$localRIB{table};
	if (length ($prefix) == 4) {
		$prefix = inet_ntoa ($prefix);
	}
	my $result = $table->match_string ("$prefix/$len");


	my ($nexthop, $neighbor);
	if (defined $result) {
		$prefix = substr ($$result, 0, 4);
		$len = unpack ("C", substr ($$result, 4, 1));
		$nexthop = substr ($$result, 5, 4);
		$neighbor = substr ($$result, 9 , 4);
	}
	return ($nexthop, $neighbor, $prefix, $len);
}

