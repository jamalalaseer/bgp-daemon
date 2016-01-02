# PathAttribute.pm - BGP PathAttribute object & methods
# Copyright (C) 2002 Steven Hessing 
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package BGP::PathAttribute;
require Exporter;
@ISA = (Exporter);

use strict;
use warnings;

use Socket;

use BGP::Constants;

sub new {
	my $this = shift;
	my $class = ref($this) || $this;
	my $self = {};
	bless $self, $class;
	return $self;
}

sub get_origin {
	my $self = shift;

	return $$self{origin};
}

sub set_origin {
	my $self = shift;
	my $value = shift;

    if ($value >= 0 || $value <= 2) {
	return $$self{origin} = $value;
    }
    return; 
}

sub get_nexthop {
	my $self = shift;

	return $$self{nexthop}
}

sub set_nexthop {
	my $self = shift;
	my $nexthop = shift;
	
	if (length ($nexthop) != 4) {
		$nexthop = inet_aton ($nexthop);
	}
	return $$self{nexthop} = $nexthop;
}

sub get_localpref {
	my $self = shift;
	my $localpref = shift;
	
	return $$self{localpref};
}

sub set_localpref {
	my $self = shift;
	my $localpref = shift;

	return $$self{localpref} = $localpref;
}

sub get_atomicaggregate {
	my $self = shift;

	return $$self{atomicaggregate};
}

sub set_atomicaggregate {
	my $self = shift;

	return $$self{atomicaggregate} = 1;
}

sub get_med {
	my $self = shift;

	return $$self{med};
}

sub set_med {
	my $self = shift;
	my $med = shift;

	return $$self{med} = $med;
}

sub get_aspath {
    my $self = shift;

    if (defined $$self{aspath}) {
        return (@{$$self{aspath}});
    } else {
        return;
    }
}

sub set_aspath {
	my $self = shift;
	my $aspathref = shift;

    return $$self{aspath} = $aspathref;
}

sub get_aslist {
	my $self = shift;
	my $aslistref = shift;

	if (defined $$aslistref{aslist}) {
        return (@{$$aslistref{aslist}});
    } else {
        return;
    }
}

sub get_pathtype {
	my $self = shift;
	my $aslistref = shift;

	return $$aslistref{pathsegmenttype};
}

sub add_aslist {
	my $self = shift;
	my ($type, $aslistref) = @_;

    push @{$$self{aspath}}, {'pathsegmenttype' => $type, 'aslist', $aslistref };
    return $#{$$self{aspath}};
}

sub get_aggregator {
	my $self = shift;

	return ($$self{aggregatoras}, $$self{aggregatorip});
}

sub get_aggregatorip {
	my $self = shift;

	return $$self{aggregatorp};
}

sub get_aggregatoras {
	my $self = shift;

	return $$self{aggregatoras};
}

sub set_aggregator {
	my $self = shift;
	my ($as, $ip) = @_;

	if (length ($ip) != 4) {
		$ip = inet_aton ($ip);
	}

	$$self{aggregatoras} = $as;
	$$self{aggregatorip} = $ip;
	return;
}

sub get_communities {
	my $self = shift;

	if (defined $$self{communities}) {
        return (@{$$self{communities}});
    } else {
        return;
    }
}

sub set_communities {
	my $self = shift;
	my $arrayref = shift;

    return $$self{communities} = $arrayref;
}

sub get_originatorid {
	my $self = shift;

	return $$self{originatorid};
}

sub set_originatorid {
	my $self = shift;
	my $id = shift;

	return $$self{originatorid} = $id;
}

sub get_clusterlist {
    my $self = shift;

    if (defined $$self{clusterlist}) {
        return (@{$$self{clusterlist}});
    } else {
        return;
    }
}

sub set_clusterlist {
	my $self = shift;
	my $arrayref = shift;

    return $$self{clusterlist} = $arrayref;
}

sub get_advertiser {
	my $self = shift;

    return $$self{advertiser};
}
sub set_advertiser {
	my $self = shift;
	my $advertiser = shift;

    return $$self{advertiser} = $advertiser;
}

# RCID PATH attributes are sent by route servers to other route servers
# (RFC1863), we don't support this functionality

sub get_rcid_path {
	my $self = shift;

    return undef;
}

sub set_rcid_path {
	my $self = shift;

    return undef;
}

sub add_unknown_attributes {
	my $self = shift;
	my @attribs = @_;

	push @{$$self{unknownattributes}}, @attribs;
	return;
}

sub get_unknown_attributes {
	my $self = shift;

	if (defined $$self{unknownattributes}) {
		return (@{$$self{unknownattributes}});
	} else {
		return;
	}
}

# Path attributes lay-out for BGP UPDATE messages
# <path attribute code, path attribute length, path attribute value)
#
# Where path attribute code is:
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |  Attr. Flags  |Attr. Type Code|
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Attribute is either a one- or two-byte field, depending on the EXTENDED
# LENGTH flag in the attribute flags
#
# This sub-routine is awfully long but there is little point in breaking it
# up. Each of the path attribute types is processed and extensive error
# checking is performed.
# The result is a filled PathAttribute object
# $peerref is currently not used, other then for logging purposes.
# Returns `0' or BGP errorcode, errorsubcode plus data.
#
# The $attribute scalar is used to record the contents of a particular
# path attribute. This path attribute needs to be send in a NOTIFICATION
# message if there is an error with the path attribute.
# Attribute flags are not preserved (hmm..TODO, we should preserve it for
# the Partial attribute!) except for attribute flags of unknown optional
# transitive path attributes.

sub parse {
	my $pa = shift;
	my ($neighbor, $buff) = @_;

	my $total_path_attribute_length = length ($buff);

	my $bytes_read = 0;
	while ($bytes_read < $total_path_attribute_length ) {
		my $attribute = substr($buff, $bytes_read, 2);
		my %attribute_flag;
		my $attribute_flags = unpack ('C', substr($buff,$bytes_read, 1));
		my $attribute_type_code = unpack ('C', substr($buff, $bytes_read+1, 1));
		$bytes_read += 2;

		my $message = "$attribute_flags -> ";
		if ($attribute_flags & BGP_UPDATE_Path_Attribute_OPTIONAL) {
			$message .= "optional ";
			$attribute_flag{optional} = 1;
		} else {
			$message .= "mandatory ";
		}
		if ($attribute_flags & BGP_UPDATE_Path_Attribute_TRANSITIVE) {
			$message .= "transitive ";
			$attribute_flag{transitive} = 1;
		}
		if ($attribute_flags & BGP_UPDATE_Path_Attribute_PARTIAL) {
			$message .= "partial ";
			$attribute_flag{partial} = 1;
		}
		my $attribute_length;
		if ($attribute_flags & BGP_UPDATE_Path_Attribute_EXTENDED_LENGTH) {
			$message .= "extended length";
			$attribute_length = unpack('n', substr($buff, $bytes_read, 2));
			$attribute .= substr($buff, $bytes_read, 2);
			# The extended flag shall only be set if the number of octets
			# required for the attribute value > 255
			if ($attribute_length < 256) {
				$attribute .= substr($buff, $bytes_read + 2, $attribute_length);
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRC_UPDATE_Message_Error, $attribute);
			}
			$bytes_read += 2;
		} else {
			$attribute_length = unpack('C', substr($buff, $bytes_read, 1));
			$attribute .= substr($buff, $bytes_read, 1);
			$bytes_read += 1;
		}
		$neighbor->log (2, 256, "type $attribute_type_code,",
			"length $attribute_length,", "flags: $message");

		$attribute .= substr ($buff, $bytes_read, $attribute_length);
		my $attribute_value;
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_ORIGIN) {
			$attribute_value = unpack ('C',
				substr($buff, $bytes_read, $attribute_length));
			$neighbor->log (2, 256, "ORIGIN: $attribute_value");
			if (defined $pa->get_origin()) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			if (defined $attribute_flag{optional}
					|| !defined $attribute_flag{transitive}
					|| defined $attribute_flag{partial}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length != 1) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			if (!defined $pa->set_origin($attribute_value)) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Invalid_ORIGIN_Attribute, $attribute);
			}
			$bytes_read += 1;
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_AS_PATH) {
			if (defined $pa->get_aspath) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			$pa->set_aspath([]);
			my $as_path_bytes_read = 0;
			while ($as_path_bytes_read < $attribute_length) {
				my $path_segment_type = unpack('C', substr($buff,
					$bytes_read + $as_path_bytes_read, 1));
				my $path_segment_length = unpack('C', substr($buff,
					$bytes_read + $as_path_bytes_read + 1, 1));
				$as_path_bytes_read += 2;
				my $aslistref = [];
				my $ind;
				for $ind (1 .. $path_segment_length) {
					my $as = unpack('n', substr($buff,
						$bytes_read + $as_path_bytes_read, 2));
					# TODO: Add check whether AS is correct
					push @{$aslistref}, $as;
					$as_path_bytes_read += 2;
				}
				$neighbor->log (2, 256, "AS PATH ->",
					BGP_AS_PATH -> [$path_segment_type]);

				if ($path_segment_type < 1 || $path_segment_type > 4) {
					return (BGP_ERRC_UPDATE_Message_Error,
						BGP_ERRSC_Malformed_AS_PATH);
				}
				$neighbor->log (2, 256,
					"Number of AS's in PATH:", 
					$path_segment_length, "AS path:", @{$aslistref});

				$pa->add_aslist ($path_segment_type, $aslistref);

			}
			# This is a mandatory, well-known attribute:
			if (defined $attribute_flag{optional}
					|| !defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			$bytes_read += $as_path_bytes_read;
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_NEXT_HOP) {
			if (defined $pa->get_nexthop()) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			my $next_hop = substr($buff, $bytes_read, $attribute_length);
			# TODO: check $next_hop on both syntactic as symantic
			# correctness and add the different error responses.
			my $nh_ip = inet_ntoa (substr($buff, $bytes_read, 4));
			# This is a well-known mandatory attribute
			if (defined $attribute_flag{optional}
					|| !defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
				BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length != 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			$pa->set_nexthop ($next_hop);

			$neighbor->log (2, 256, "Next hop: $nh_ip");
			$bytes_read += 4;
		}
		if ($attribute_type_code ==
				BGP_UPDATE_Path_Attribute_MULTI_EXIT_DISC) {
			if (defined $pa->get_med()) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			my $med = unpack('N',
				substr($buff, $bytes_read, $attribute_length));
			# This is an optional non-transitive attribute
			if (!defined $attribute_flag{optional}
					|| defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
				BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length != 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			$pa->set_med ($med);
			$bytes_read += 4;
			$neighbor->log (2, 256, "MED: $med");
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_LOCAL_PREF) {
			if (defined $pa->get_localpref()) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			my $local_pref = unpack('N',
				substr($buff,$bytes_read, 4));
			# This is a well-known discretionary attribute
			if (defined $attribute_flag{optional}
					|| !defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length != 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			$pa->set_localpref ($local_pref);

			$bytes_read += 4;
			$neighbor->log (2, 256,
				"Local Pref: $local_pref");
		}
		if ($attribute_type_code ==
				BGP_UPDATE_Path_Attribute_ATOMIC_AGGREGATE) {
			if (defined $pa->get_atomicaggregate()) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			if ($attribute_length != 0) {
				$neighbor->log (2, 32,
					"Atomic aggregate attribute length != 0");
			}
			$pa->set_atomicaggregate ();
			$bytes_read += 0;
			$neighbor->log (2, 256,
				"This route is an atomic aggregate");
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_AGGREGATOR) {
			if (defined $pa->get_aggregatoras()) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Malformed_Attribute_List);
			}
			my $aggr_as = unpack('n',
				substr($buff,$bytes_read, 2));
			my $aggr_host = unpack('N',
				substr($buff,$bytes_read + 2, 4));
			# This is a well-known discretionary attribute according to RFC1771
			# Cisco sends it as an optional attribute so that's how we accept it
			if (!defined $attribute_flag{optional} ||
					!defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length != 6) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			$pa->set_aggregator ($aggr_as, $aggr_host);
			my $aggr_host_ip = inet_ntoa
				(substr($buff, $bytes_read + 2, 4));
			$bytes_read += 6;
			$neighbor->log (2, 256,
				"AGGREGATOR AS: $aggr_as, host: $aggr_host_ip");
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_COMMUNITIES) {
			$attribute .= substr($buff, $bytes_read, $attribute_length);

			# this is a optional transitive attribute
			if (!defined $attribute_flag{optional} || 
					!defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			# Every community consists of 4 bytes
			if ($attribute_length % 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			my @communities = unpack ('N*', substr($buff, $bytes_read, 
				$attribute_length));
			$bytes_read += $attribute_length;
			$pa->set_communities (\@communities);
			$neighbor->log (2, 256, "Communities:",
				@communities);
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_ORIGINATOR_ID) {
			$attribute .= substr($buff, $bytes_read, $attribute_length);

			# this is a optional non-transitive attribute
			if (!defined $attribute_flag{optional} || 
					defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			# The originator_id consists of 4 bytes
			if ($attribute_length != 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			my $originator_id = unpack ('N', substr ($buff, $bytes_read, 4));

			$pa->set_originatorid ($originator_id);
			$bytes_read += $attribute_length;
			$neighbor->log (2, 256, "Originator ID:",
				inet_ntoa($originator_id));
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_CLUSTER_LIST) {
			$attribute .= substr($buff, $bytes_read, $attribute_length);

			# this is a optional non-transitive attribute
			if (!defined $attribute_flag{optional} || 
					defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length % 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			my @cluster_list = unpack ('N*', substr($buff, $bytes_read, 
				$attribute_length));
			$bytes_read += $attribute_length;
			$pa->set_clusterlist (\@cluster_list);
			$neighbor->log (2, 256, "Cluster list:",
				@cluster_list);
		}
		if ($attribute_type_code == BGP_UPDATE_Path_Attribute_ADVERTISER) {
			$attribute .= substr($buff, $bytes_read, $attribute_length);

			# this is a optional non-transitive attribute
			if (!defined $attribute_flag{optional} || 
					defined $attribute_flag{transitive}) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Flags_Error, $attribute);
			}
			if ($attribute_length != 4) {
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Attribute_Length_Error, $attribute);
			}
			my $advertiser = unpack ('N', substr ($buff, $bytes_read, 4));

			$pa->set_advertiserr ($advertiser);
			$bytes_read += $attribute_length;
			$neighbor->log (2, 256, "Advertiser:",
				inet_ntoa($advertiser));
		}
		#if ($attribute_type_code == BGP_UPDATE_Path_Attribute_RCID_PATH) {
		if ($attribute_type_code == 13) {
			$attribute .= substr($buff, $bytes_read, $attribute_length);
			# We should not receive this path attribute. It should be sent
			# by route servers (RFC1863) to other route servers.
			$neighbor->log (2, 16, "We are not a route",
				"server but we received a RCID_PATH path attribute");
			return (BGP_ERRC_UPDATE_Message_Error,
				BGP_ERRSC_Optional_Attribute_Error, $attribute);
		}
		# What if we don't know about the path attribute type?
		if ($attribute_type_code < 1 || $attribute_type_code > 16) {
			if (defined $attribute_flag{optional}) {
				if (defined ($attribute_flag{transitive})) {
					# unknown optional transitive attributes should
					# be passed along unchanged but for the Partial
					# bit set.
					my $flags = unpack ('C', substr($attribute,0,1));
					$flags |= BGP_Path_Attribute_Flags_PARTIAL;
					substr($attribute,0,1) = pack('C', $flags);
					$pa->add_unknown_attributes ($attribute);
				} else {
					# unknown optional non-transitive attributes
					# can be discarded
				}
			} else {
				# If this is a well-known attribute then we have
				# to raise an error and send a NOTIFICATION.
				$attribute .= substr($buff, $bytes_read,
					$attribute_length);
				return (BGP_ERRC_UPDATE_Message_Error,
					BGP_ERRSC_Unrecognized_Well_Known_Attribute,
					$attribute);
			}
		}

	}
	if (!defined $pa->get_origin()) {
		return (BGP_ERRC_UPDATE_Message_Error,
			BGP_ERRSC_Missing_Well_Known_Attribute,
			pack('C',BGP_UPDATE_Path_Attribute_ORIGIN));
	}
	if (!defined $pa->get_aspath ()) {
		return (BGP_ERRC_UPDATE_Message_Error,
			BGP_ERRSC_Missing_Well_Known_Attribute,
			pack('C',BGP_UPDATE_Path_Attribute_AS_PATH));
	}
	if (!defined $pa->get_nexthop()) {
		return (BGP_ERRC_UPDATE_Message_Error,
			BGP_ERRSC_Missing_Well_Known_Attribute,
			pack('C',BGP_UPDATE_Path_Attribute_NEXT_HOP));
	}
	return 0;
}
