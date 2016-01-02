# AdjRibIn.pm - BGP adj-RIB-in forwarding table management
# Copyright (C) 2002 Steven Hessing 
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

package BGP::AdjRibIn;
require Exporter;
@ISA = (Exporter);

use Socket;

use strict;
use warnings;

sub new {
    my $this = shift;
    my $class = ref($this) || $this;

    my $self = {};
    bless $self, $class;
	return $self;
}

sub get_neighbors {
	my $adjRIBin = shift;
	my ($prefix, $len, $omit) = @_;

	if (!defined $omit) {
		return (keys %{$$adjRIBin{ip}{$prefix}{$len}});
	} else {
		my @neighbors;
		my $neighbor;
		foreach $neighbor (keys %{$$adjRIBin{ip}{$prefix}{$len}}) {
			$neighbor ne $omit && push @neighbors, $neighbor;
		}
		return (@neighbors);
	}
}

sub get_prefixes {
	my $adjRIBin = shift;

	return (keys %{$$adjRIBin{ip}});
}

sub get_prefix_lengths {
	my $adjRIBin = shift;
	my $prefix = shift;

	return (keys %{$$adjRIBin{ip}{$prefix}});
}

sub prefix_exists {
	my $adjRIBin = shift;
	my ($prefix, $len, $neighbor) = @_;

	if (defined $neighbor) {
		return defined $$adjRIBin{ip}{$prefix}{$len}{$neighbor};
	} 
	if (defined $len) {
		return defined $$adjRIBin{ip}{$prefix}{$len};
	}
	return defined $$adjRIBin{ip}{$prefix};
}

sub delete {
	my $adjRIBin = shift;
	my ($prefix, $len, $neighbor) = @_;

	my $deleted = 0;
	if (defined $neighbor) {
		delete $$adjRIBin{ip}{$prefix}{$len}{$neighbor};
		$deleted++;
		return $deleted if (keys %{$$adjRIBin{ip}{$prefix}{$len}} > 0);
	} 
	if (defined $len) {
		$deleted += delete $$adjRIBin{ip}{$prefix}{$len};
		return $deleted if (keys %{$$adjRIBin{ip}{$prefix}} > 0);
	}
	$deleted += delete $$adjRIBin{ip}{$prefix};
	if (keys %{$$adjRIBin{ip}} == 0 ) {
		delete $$adjRIBin{ip};
	}
	return $deleted;
}

sub delete_all {
	my $adjRIBin = shift;
	my $neighbor = shift;

    my $count = 0;
    my $prefix;
    foreach $prefix ($adjRIBin->get_prefixes ()) {
        my $prefix_length;
        foreach $prefix_length ($adjRIBin->get_prefix_lengths ($prefix)) {
            if (defined $neighbor) {
                $count += $adjRIBin->delete ($prefix, $prefix_length,$neighbor);
            } else {
                $count += $adjRIBin->get_neighbors ($prefix, $prefix_length);
            }
        }
    }
    if (!defined $neighbor) {
        $$neighbor{ip} = ();
        $$neighbor{todo}{ip} = ();
    }
    return $count;
}

sub get_pathattribute {
	my $adjRIBin = shift;
	my ($prefix, $len, $neighbor) = @_;

	return $$adjRIBin{ip}{$prefix}{$len}{$neighbor};
}

sub add {
	my $adjRIBin = shift;
    my ($prefix, $prefix_length, $neighbor, $pa) = @_;

    # TODO points 1) and ii) in section 9 of RFC1771
    $$adjRIBin{ip}{$prefix}{$prefix_length}{$neighbor} = $pa;
	$adjRIBin->add_todo ($prefix, $prefix_length);

    return 1;
}

sub get_todo_prefixes {
	my $adjRIBin = shift;

	return (keys %{$$adjRIBin{todo}{ip}});
}

sub get_todo_prefix_lengths {
	my $adjRIBin = shift;
	my $prefix = shift;

	return (keys %{$$adjRIBin{todo}{ip}{$prefix}});
}

sub add_todo {
	my $adjRIBin = shift;
	my ($prefix, $len) = @_;

	return $$adjRIBin{todo}{ip}{$prefix}{$len} = 1;
}

sub delete_todo {
	my $adjRIBin = shift;
	my ($prefix, $len) = @_;

	if (defined $len) {
		delete $$adjRIBin{todo}{ip}{$prefix}{$len};
		return if (keys %{$$adjRIBin{todo}{ip}{$prefix}} > 0);
	}
	delete $$adjRIBin{todo}{ip}{$prefix};
	if (keys %{$$adjRIBin{todo}{ip}} == 0 ) {
		delete $$adjRIBin{todo}{ip};
	}
	return;
}


