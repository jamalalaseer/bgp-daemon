# Neighbor.pm - BGP Session management: object & methods
# Copyright (C) 2002 Steven Hessing 
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package BGP::Neighbor;
require Exporter;
@ISA = (Exporter);

use Socket;
use FileHandle;
use Sys::Syslog qw(:DEFAULT setlogsock);
use POSIX qw(strftime);

use BGP::Constants;
use BGP::PathAttribute;

use strict;
use warnings;

sub new {
	my $this = shift;
	my $class = ref($this) || $this;

	my $self = { doneheader => 0, buff => do { my $buff = ""; \$buff } };
	bless $self, $class;

	my $ip = shift;
	# Init the rest of the session data
	$self->set_ipaddress ($ip);
	$self->set_state (BGP_NEIGHBOR_IDLE);
	$self->set_time ();
	$self->add_history ("BGP Transport defined");
	$self->set_version (4);
	$self->clear_routesin ();
	$self->clear_routescurrent ();
	$self->clear_routesout ();
	$self->clear_localRIBentries ();

	return $self;
}

sub close {
	my $neighbor = shift;
	my ($adjRIBin, $errorcode, $errorsubcode, $errordata) = @_;

	my $peer_ip = $neighbor->get_ipaddress ();

	my $routecount = $adjRIBin->delete_all ($peer_ip);

	if ($errorcode >= 0) {
		if (defined $errorsubcode) {
			if (defined $errordata) {
				$neighbor->send_notification ($errorcode, $errorsubcode,
					$errordata);
			} else {
				$neighbor->send_notification ($errorcode, $errorsubcode);
			}
		} else {
			$neighbor->send_notification ($errorcode);
		}
	}
	close ($neighbor->get_filehandle());
	$neighbor->log (64, 4, "Closed connection to $peer_ip, removed",
		$routecount, "prefixes from Adj-RIB-in");
	$neighbor->set_filehandle (undef);
	$neighbor->set_state (BGP_NEIGHBOR_ACTIVE);
}

sub send {
	my $neighbor = shift;
	my ($type, $data) = @_;

	my $marker = BGP_MARKER;

	my $ip = $neighbor->get_ipaddress ();
	if (defined $neighbor->get_authmethod()) {
		# TODO: $market = create_authentication_blah_blah_blah
		$neighbor->log (64, 1, "BGP authentication is not yet supported");
	}
	my $message = "";
	$message .= $marker;
	my $len = 19;
	if (defined ($data)) {
		$len += length($data);
	}
	$message .= pack ('n', $len);
	$message .= pack ('C', $type);
	if (defined ($data)) {
		$message .= $data;
	}

	$neighbor->log (64, 4, "Send message type $type,",
		BGP_MESSAGE->[$type], "length $len");
	my $message_len = length ($message);
	if (!defined (send ($neighbor->get_filehandle(), $message, 0))) {
		return 0;
	}
	return 1;
}

# Lay out of BGP header
#
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                                                               |
#      +                                                               +
#      |                                                               |
#      +                                                               +
#      |                           Marker                              |
#      +                                                               +
#      |                                                               |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |          Length               |      Type     |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# RFCs that have an impact on `$neighbor->receive':
# RFC1863, RFC1771, RFC2918
#
# TODO: implement RFC1863 and RFC2918
#
sub receive {
	my $neighbor = shift;

	my $bgprouter = shift;
	my $adjRIBin = $bgprouter->get_adjRIBin();
	my $my_ip = $bgprouter->get_routerid();
	my $peer_ip = $neighbor->get_ipaddress();

	my $buff = $neighbor->{buff};

	# invariant: the start of $buff is always the start of a message
	# max message size is 4096, but we may get more than one. If so,
	# we only process the first one here (other stuff seems to break
	# if we do multiple updates here) and leave the rest in the buffer.
	# sysread() updates the length of the buffer itself
	# we're in a select loop, so only do one read call (if we didn't
	# get enough, we'll be back here again later)

	my $wantmore = 1;

	{
		my ($errorcode, $errorsubcode, $errordata);
		my ($len, $type, $marker);

		if (length($$buff) >= 19) {
			($len, $type, $marker) = parse_bgp_header ($$buff);

			unless ($neighbor->{doneheader}) {
				$neighbor->log (64, 64, "Rcv BGP message, type $type",
					"(" . BGP_MESSAGE->[$type] . "),", "length $len");

				($errorcode, $errorsubcode) =
					$neighbor->validate_header_marker ($marker);
				if ($errorcode) {
					return ($errorcode, $errorsubcode);
				}
				($errorcode, $errorsubcode, $errordata) =
					$neighbor->validate_message_length ($len, $type);
				if ($errorcode) {
					return ($errorcode, $errorsubcode, $errordata);
				}
				$neighbor->set_keepalive_in_timer ();

				if ($type == BGP_KEEPALIVE) {
					substr($$buff,0,19) = "";
					return $neighbor->receive_keepalive ();
				}

				$neighbor->{doneheader} = 1;
			}

			# if we have the whole packet, process it.
	
			if (length($$buff) >= $len) {
				my @result;
				my $mess = substr($$buff, 19, $len - 19);

				if ($type == BGP_OPEN) {
					@result = $neighbor->receive_open ($mess, $marker,
						$bgprouter);
				}
				if ($type == BGP_UPDATE) {
					# TODO, why do we send both $adjRIBin and $bgprouter?
					@result = $neighbor->receive_update ($mess, $adjRIBin,
						$bgprouter);
				}
				if ($type == BGP_NOTIFICATION) {
					@result = $neighbor->receive_notification ($mess,
						$bgprouter);
				}
				if ($type == BGP_ROUTE_REFRESH) {
					@result = $neighbor->receive_route_refresh ($mess,
						$bgprouter);
				}
				# BGP LIST messages are defined in RFC1863
				if ($type == BGP_LIST) {
					return -1;
				}

				# if broken, bail out
				return @result if $result[0];

				# nuke the just-processed packet and bail
				substr($$buff,0,$len) = "";
				$neighbor->{doneheader} = 0;
				return 0;
			}
		}
	    # get here if the packet wasn't complete

	    if ($wantmore) {
			unless (sysread($neighbor->get_filehandle(), $$buff,
					8192 - length($$buff), length($$buff))) {
		    	$neighbor->log (64, 16, "Could not read BGP message");
		    	return -1;
			}

			$neighbor->log (64, 64, "receive done - buf @{[length($$buff)]}");

			$wantmore = 0;
			redo;
	    }

	}
	return 0;
}

sub parse_bgp_header {
	my $buff = shift;

	my @markers = unpack ('NNNN', substr($buff,0, 16));
	my $marker = pack ('NNNN', @markers);
	my $len = unpack("n",substr($buff,16,2));
	my $type = unpack ("C", substr ($buff,18,1));
	return ($len, $type, $marker);
}

sub validate_header_marker {
	my $neighbor = shift;
	my $marker = shift;

	my $ip = $neighbor->get_ipaddress ();
	if (defined $neighbor->get_authmethod ()) {
		#check_bgp_message_authentication()
		$neighbor->log (64, 1, "BGP authentication not yet supported");
		return (BGP_ERRC_Message_Header_Error,BGP_ERRSC_Authentication_Failure);
	} else {
		$neighbor->log (64, 128,"Validating marker $marker");
		if ($marker ne BGP_MARKER) {
			$neighbor->log (64, 16, "Marker failed validation with 0xFFFFFFFF");
			return (BGP_ERRC_Message_Header_Error,
				BGP_ERRSC_Connection_Not_Synchronized);
		}
	}
	return (0,0);
}

sub validate_message_length {
	my $neighbor = shift;
	my ($len, $type) = @_;

	my $ip = $neighbor->get_ipaddress ();
	$neighbor->log (64, 128, "validating message length (type = $type",
		"(" . BGP_MESSAGE -> [$type] . "),", "length = $len)");
	if ($len < 19 || $len > 4096 ||
			($type == BGP_OPEN && $len < 29) ||
			($type == BGP_UPDATE && $len < 23) ||
			($type == BGP_NOTIFICATION && $len < 21) ||
			($type == BGP_KEEPALIVE && $len != 19) ||
			($type == BGP_ROUTE_REFRESH && $len != 23)) {
		return (BGP_ERRC_Message_Header_Error,
			BGP_ERRSC_Bad_Message_Length, pack ('n', $len));
	}
	return 0;
}

sub parse_open {
	my $neighbor = shift;
	my ($buff, $marker) = @_;

	my $ip = $neighbor->get_ipaddress ();
	my $version = $neighbor->set_version (unpack("C", substr($buff,0,1)));
	my $as = $neighbor->set_as (unpack("n", substr($buff,1,2)));
	my $holdtime = $neighbor->set_holdtime (unpack("n", substr($buff,3,2)));
	my $routerid = $neighbor->set_routerid (inet_ntoa (substr($buff, 5, 4)));

	$neighbor->log (1, 64, "version: $version, AS: $as,",
		"Holdtime: $holdtime, ID: $routerid");

	$neighbor->log (1, 4, "Checking version $version");
	if ($version != BGP_VERSION) {
		return (BGP_ERRC_OPEN_Message_Error,
			BGP_ERRSC_Unsupported_Version_Number, pack ('n',BGP_VERSION));
	}
	$neighbor->log (1, 4, "Checking holdtime ($holdtime seconds)");
	if ($holdtime == 1 || $holdtime == 2) {
		return (BGP_ERRC_OPEN_Message_Error, BGP_ERRSC_Unacceptable_Hold_Time);
	}
	my $opt_params_len = unpack('C', substr($buff,9,1));
	$neighbor->log (1, 64, "Length of Optional Parameters: $opt_params_len");

# Optional parameters in the BGP open message (RFC1771)
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
#        |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
#
	my $bytes_read = 0;
	my $offset = 10;
	my ($errorcode, $errorsubcode,$errordata);
	while ($bytes_read < $opt_params_len) {
		my $known_param = 0;
		my $param_type =
			unpack('C', substr($buff,$offset + $bytes_read,1));
		my $param_len =
			unpack('C', substr($buff,$offset + $bytes_read + 1,1));

		$neighbor->log (1, 128, "Param type: $param_type",
			"Param length: $param_len");
		if ($param_type == BGP_OPEN_Authentication) {
			$known_param = 1;
			($errorcode, $errorsubcode) =
				$neighbor->parse_open_authentication_parameter (
				substr($buff, $offset+$bytes_read+2, $param_len),
				$param_len, $marker);
			if ($errorcode) {
				return ($errorcode, $errorsubcode);
			}
		}
		# Capabilities Optional Parameter (RFC2842)
		if ($param_type == BGP_OPEN_Capabilities_Advertisement) {
			$known_param = 1;
			($errordata) = $neighbor->
				parse_open_capabilities_optional_parameter (
				substr($buff, $offset + $bytes_read + 2, $param_len),
				$param_len);
			if ($errordata ne "") {
				return (BGP_ERRC_OPEN_Message_Error,
					BGP_ERRSC_Unsupported_Capability, $errordata);
			}
		}
		# Route server (RFC1863)
		if ($param_type == BGP_OPEN_Route_Server) {
			$known_param = 1;
			$neighbor->parse_open_route_server (substr($buff, $offset +
				$bytes_read + 2, $param_len));
		}
		if (!$known_param) {
			return (BGP_ERRC_OPEN_Message_Error,
				BGP_ERRSC_Unsupported_Optional_Parameters,
				pack ('C', $param_type));
		}
		$bytes_read += (2 + $param_len);
	}
	return 0;
}

# Layout of BGP OPEN Authentication Information (RFC1771):
#
#     +-+-+-+-+-+-+-+-+
#     |  Auth. Code   |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                     |
#     |                Authentication Data                  |
#     |                                                     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# RFCs supported in receive_bgp_authentication_parameter
# RFC1771, RFC1966
#
# RFCs without impact on receive_bgp_open_message:
# RFC2842
#
# TODO:
# - perform the actual authentication
# - add support for additional RFCs (1966)
#
sub parse_open_authentication_parameter {
	my $neighbor = shift;
	my ($buff, $param_len, $marker) = @_;

	my $ip = $neighbor->get_ipaddress ();
	my $known_param = 0;
	my $auth_code = unpack ('C', substr($buff,0,1));
	my $auth_data = unpack ('b*', substr($buff,1,$param_len-1));
	$neighbor->log (1,128,"AUTHENTICATION code: $auth_code, data: $auth_data");
	if ($known_param == 0) {
		return (BGP_ERRC_OPEN_Message_Error,
			BGP_ERRSC_Unsupported_Optional_Parameters);
	}
	return 0;
}

# Layout of BGP OPEN Capabilities Optional Parameter (RFC2842)
#
#     +------------------------------+
#     | Capability Code (1 octet)    |
#     +------------------------------+
#     | Capability Length (1 octet)  |
#     +------------------------------+
#     | Capability Value (variable)  |
#     +------------------------------+
#
# RFCs supported in receive_bgp_capabilities_optional_parameter
# 1771, 2842
#
# RFCs without impact on receive_bgp_capabilities_optional_parameter
#
# TODO:
#
sub parse_open_capabilities_optional_parameter {
	my $neighbor = shift;
	my ($buff, $param_len) = @_;

	my $ip = $neighbor->get_ipaddress ();

	my $unknown_capabilities = "";
	my $bytes_read = 0;
	while ($bytes_read < $param_len) {
		my $capability_code = unpack ('C', substr($buff, $bytes_read, 1));
		my $capability_length = unpack ('C', substr($buff, $bytes_read + 1, 1));

		$neighbor->log (1, 128,
			"has CAPABILITY code $capability_code, length $capability_length");

		my $capability_value = unpack ('b*', substr($buff, $bytes_read + 2,
			$capability_length));
		my $known_capability = 0;
		if ($capability_code == BGP_OPEN_Capability_MP) {
			if ($capability_length == 4) {
				$known_capability = 1;
				my $afi = unpack ('n', substr($buff,$bytes_read + 2, 2));
				my $safi = unpack ('C', substr($buff, $bytes_read + 5, 1));
				$neighbor->set_multiprotocol ($afi, $safi);
				$neighbor->log (1, 128,
					"Multiprotocol capable: AFI = $afi SAFI = $safi");
			} else {
				$neighbor->log (1, 16,"Capability length for MP should be 4!");
			}
		}
	   if ($capability_code == BGP_OPEN_Capability_Route_Refresh ||
				$capability_code == BGP_OPEN_Capability_Route_Refresh01 ) {
			if ($capability_length == 0) {
				$known_capability = 1;
				$neighbor->routerefresh_enabled (1);
				$neighbor->log (1, 128, "Route refresh capability supported");
			}
		}
		if ($capability_code > 128) {
			# Ignore capability, it is vendor specific.
			$known_capability = 1;
			$neighbor->log (1, 128, "Capability $capability_code ignored",
				"because it is vendor specific");
		}

		# If we don't support this capability then we add the complete
		# capability sub-string to the string of unknown capabilities
		# This string is then returned in a BGP notification message.
		if ($known_capability == 0) {
			$unknown_capabilities .= substr($buff, $bytes_read,
				2 + $capability_length);
		}
		$bytes_read += (2 + $capability_length);
	}
	return $unknown_capabilities;
}

# Lay-out of BGP OPEN Route Server message (RFC1863)
#   +-----------------------+------------------------------------+
#   | Version = 1 (1 octet) |     Cluster ID (2 octets)      |
#   +-----------------------+------------------------------------+
#
# TODO:
#
sub parse_open_route_server {
	my $neighbor = shift;
	my $buff = shift;

	my $version = unpack ('C', substr($buff, 0, 1));
	my $cluster_id = unpack ('n', substr($buff,1,2));

	$neighbor->routeserver_enabled ($version, $cluster_id);

	$neighbor->log (1, 128,
		"ROUTE SERVER version: $version, cluster id: $cluster_id");
}

# Layout of BGP OPEN message (RFC1771):
#
#      +-+-+-+-+-+-+-+-+
#      |    Version    |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |     My Autonomous System      |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |          Hold Time            |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                       BGP Identifier                          |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      | Opt Parm Len  |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                                                               |
#      |                       Optional Parameters                     |
#      |                                                               |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# RFCs supported in receive_bgp_open_message:
# 1771, 2842
#
# TODO:
# - add additional support for the different kinds of capabilities defined in
#   various RFCs
# - add suberrorcode "Bad Peer AS" for invalid ASs
# - add suberrorcode "Bad BGP Identifier" for invalid BGP Identifiers.
#
sub receive_open {
	my $neighbor = shift;
	my ($buff, $marker, $bgprouter) = @_;

	my $my_ip = $bgprouter->get_routerid ();
	my $my_as = $bgprouter->get_as ();

	my ($errorcode, $errorsubcode, $errordata) =
		$neighbor->parse_open ($buff, $marker);
	if ($errorcode) {
		return ($errorcode, $errorsubcode, $errordata);
	}
	if (!$neighbor->send_open ($my_ip, $my_as)) {
		return 1;
	}
	$neighbor->set_state (BGP_NEIGHBOR_ESTABLISHED);

	$neighbor->set_keepalive_in_timer ();
	$neighbor->set_keepalive_out_timer ();
	return 0;
}

sub send_open {
	my $neighbor = shift;
	my ($my_ip, $my_as) = @_;

	my $version = $neighbor->get_version ();
	my $holdtime = $neighbor->get_holdtime ();
	my $data .= pack ('C', $version);
	$data .= pack ('n', $my_as);
	$data .= pack ('n', $holdtime);
	$data .= $my_ip;

	my $peer_ip = $neighbor->get_ipaddress ();
	$neighbor->log (64, 4,
		"Send BGP OPEN message version $version AS: ", $my_as,
		"Holdtime $holdtime BGP ID = ", inet_ntoa ($my_ip));
	my $opt_param = "";
	if ($neighbor->get_authmethod ()) {
		$neighbor->log (1, 1,
			"send_bgp_open we don't support BGP authentication yet!");
	}
	my $afi;
	foreach $afi ($neighbor->get_multiprotocol_afi ()) {
		my $safi;
		foreach $safi ($neighbor->get_multiprotocol_safi ($afi)){
			$opt_param .= pack ('C', BGP_OPEN_Capabilities_Advertisement);
			$opt_param .= pack ('C', 6);
			$opt_param .= pack ('C', BGP_OPEN_Capability_MP);
			$opt_param .= pack ('C', 4);
			$opt_param .= pack ('n C C', $afi, 0, $safi);
			$neighbor->log (1, 4,
				"Informing of MP capability: AFI -> $afi SAFI -> $safi");
		}
	}
	if ($neighbor->routerefresh_enabled ()) {
		$opt_param .= pack ('C', BGP_OPEN_Capabilities_Advertisement);
		$opt_param .= pack ('C', 2);
		$opt_param .= pack ('C', BGP_OPEN_Capability_Route_Refresh);
		$opt_param .= pack ('C', 0);
		$opt_param .= pack ('C', BGP_OPEN_Capabilities_Advertisement);
		$opt_param .= pack ('C', 2);
		$opt_param .= pack ('C', BGP_OPEN_Capability_Route_Refresh01);
		$opt_param .= pack ('C', 0);
		$neighbor->log (1, 4, "Informing of Route Refresh capability");
	}
	if ($neighbor->routeserver_enabled ()) {
		$opt_param .= pack ('C', BGP_OPEN_Route_Server);
		$opt_param .= pack ('C', 3);
		$opt_param .= pack ('C n', 1, 0);
		$opt_param .= pack ('C', BGP_OPEN_Route_Server01);
		$opt_param .= pack ('C', 3);
		$opt_param .= pack ('C n', 1, 0);
		$neighbor->log (1, 4, "Informing of Route Server capability");
	}

	$data .= pack ('C', length ($opt_param));
	$data .= $opt_param;

	return $neighbor->send (BGP_OPEN, $data);
}

# Layout of BGP UPDATE message (RFC1771):
#      +-----------------------------------------------------+
#      |   Unfeasible Routes Length (2 octets)               |
#      +-----------------------------------------------------+
#      |  Withdrawn Routes (variable)                        |
#      +-----------------------------------------------------+
#      |   Total Path Attribute Length (2 octets)            |
#      +-----------------------------------------------------+
#      |    Path Attributes (variable)                       |
#      +-----------------------------------------------------+
#      |   Network Layer Reachability Information (variable) |
#      +-----------------------------------------------------+
#
sub receive_update {
	my $neighbor = shift;
	my ($buff, $adjRIBin, $bgprouter) = @_;

	my $my_ip = $bgprouter->get_routerid ();

	my $peer_ip = $neighbor->get_ipaddress ();
	my $peer_pack = inet_aton ($peer_ip);
	my ($errorcode, $errorsubcode, $errordata) = (0,0,"");
	my $len = length ($buff);
	my $unfeas_routes_len = unpack ('n', substr($buff,0,2));
	my @routes = parse_update_withdrawn_routes (substr($buff,2,
		$unfeas_routes_len));
	$neighbor->log (2, 64,
		"Length of unfeasable routes: $unfeas_routes_len");
	if ($unfeas_routes_len > 0) {
		my $route;
		foreach $route (@routes) {
			my $prefix_length = $route->{prefix_length};
			my $prefix = $route->{prefix};
			if ($prefix_length == 0) {
				my $routecount = $adjRIBin->delete_all ($peer_pack);
				$neighbor->decrease_routescurrent ($routecount);
				$neighbor->log (2, 128,
					"Deleted all prefixes (count = $routecount) from",
					"peer $peer_ip");
			} else {
				if ($adjRIBin->delete ($prefix, $prefix_length, $peer_pack)) {
					$neighbor->decrease_routescurrent ();
					$neighbor->log (2, 128,
						"Deleted prefix $prefix/$prefix_length with",
						"from peer $peer_ip");
				} else {
					$neighbor->log (2, 32, "Withdrawing",
					"$prefix/$prefix_length but this has not been advertised",
					"by $peer_ip");
				}
			}
		}
	}

	my $total_path_attribute_length = unpack ('n',
		substr($buff, 2 + $unfeas_routes_len,2));
	$neighbor->log (2, 64, "Packet length: $len,",
		"Total path attribute length: $total_path_attribute_length,",
		"Unfeas routes len: $unfeas_routes_len");
	if ($unfeas_routes_len + 4 == $len) {
		# No new routes are announced
		return 0;
	}
	if ($unfeas_routes_len + $total_path_attribute_length + 4 > $len) {
		return (BGP_ERRC_UPDATE_Message_Error,
			BGP_ERRSC_Malformed_Attribute_List);
	}

	my $pa = new BGP::PathAttribute;
	my $offset = 2 + $unfeas_routes_len + 2;
	($errorcode, $errorsubcode, $errordata) = $pa->parse ($neighbor,
		substr($buff, $offset, $total_path_attribute_length));
	if ($errorcode) {
		return ($errorcode, $errorsubcode, $errordata);
	}
	# TODO: we should maintain $my_ip differently. It should be a list
	# with all IP addresses, and we should keep track which of our IP addresses
	# accepted a BGP session for a particular neighbor.
	# RFC1863, route server, don't accept our own IP address as next-hop
	if ($pa->get_nexthop() eq $my_ip) {
		$neighbor->log (2, 32, "Ignoring this update",
			"because it has our IP address as next_hop");
		return 0;
	}
	# RFC2796, route reflection, don't accept our own IP address
	# as ORIGINATOR_ID or in the CLUSTER_LIST:
	my $originator_id = $pa->get_originatorid ();
	if (defined $originator_id && $originator_id eq $my_ip) {
		$neighbor->log (2, 32, "Ignoring this update",
			"because it has our ORIGINATOR_ID");
		return 0;
	}
	my @clusterlist = $pa->get_clusterlist ();
	my $cluster_id;
	foreach $cluster_id (@clusterlist) {
		if ($cluster_id eq $my_ip) {
			$neighbor->log (2, 32, "Ignoring this update",
				"because our IP address is in its cluster list");
			return 0;
		}
	}

	$offset = 2 + $unfeas_routes_len + 2 + $total_path_attribute_length;

	my $nlri_length = ($len + 19) - 23 - $total_path_attribute_length -
		$unfeas_routes_len;
	$neighbor->log (2, 64, "Length of NLRI: $nlri_length");
#
# NLRI Lay-out:
#       +---------------------------+
#       |   Length (1 octet)        |
#       +---------------------------+
#       |   Prefix (variable)       |
#       +---------------------------+
#
	my $bytes_read = 0;
	while ($bytes_read < $nlri_length) {
		my ($prefix_length, $prefix, $octets) =
			unpack_prefix (substr ($buff, $offset + $bytes_read, $nlri_length));
		$bytes_read += (1 + $octets);
		$neighbor->increase_routesin ();
		$neighbor->increase_routescurrent ();
		$neighbor->log (2, 64, "Adding prefix",
			inet_ntoa($prefix) . "/$prefix_length for peer $peer_ip");
		$adjRIBin->add ($prefix, $prefix_length, $peer_pack, $pa);
	}
	return 0;
}

# Withdrawn Routes in the BGP UPDATE message (RFC1771)
#       +---------------------------+
#       |   Length (1 octet)        |
#       +---------------------------+
#       |   Prefix (variable)       |
#       +---------------------------+
#
sub parse_update_withdrawn_routes {
	my ($buff) = @_;

	my $bytes_read = 0;
	my $unfeas_routes_len = length($buff);
	my @routes;
	while ($bytes_read < $unfeas_routes_len) {
		my ($plength, $prefix, $octets) =
			unpack_prefix (substr ($buff, $bytes_read));
		push @routes, {'prefix' => $prefix, 'prefix_length' => $plength};
		if ($plength == 0) {
			$bytes_read += 1;
		} else {
			$bytes_read += (1 + $octets);
		}
	}
	return @routes;
}

# Lay-out of BGP keepalive messages (RFC1771):
#
# BGP keepalive messages have no data. They consist of only the header.
# This is basically a dummy function because set_keepalive_in_timer
# is already called in $neighbor->receive
#
sub receive_keepalive {
	my $neighbor = shift;

	$neighbor->log (8, 4, "Receiving BGP KEEPALIVE message");
	$neighbor->set_keepalive_in_timer ();
	return 0;
}

sub send_keepalive {
	my $neighbor = shift;

	if (defined $neighbor) {
		my $holdtime = $neighbor->get_holdtime ();
		if (defined $holdtime && $holdtime == 0) {
			$neighbor->log (8, 32, "sending a keepalive with holdtime == 0?!?");
			return 1;
		} else {
			$neighbor->set_keepalive_out_timer ();
			return $neighbor->send (BGP_KEEPALIVE, "");
		}
	}
	return 0;
}

sub set_keepalive_in_timer {
	my $neighbor = shift;

	return $neighbor->set_timer_keepalivein (time());
}

sub set_keepalive_out_timer {
	my $neighbor = shift;

	my $holdtime = $neighbor->get_holdtime ();
	if (defined $holdtime) {
		if ($holdtime == 0) {
			$neighbor->set_timer_keepaliveout (0);
		} else {
			my $keepalive_out = $neighbor->get_timer_keepaliveout ();
			if (defined $keepalive_out) {
				$neighbor->set_timer_keepaliveout (time());
			} else {
				# We only come here if the BGP session has just been
				# established and we haven't set out a keepalive before.
				# This way we enforce it to be sent immediately.
				$neighbor->set_timer_keepaliveout (time() - $holdtime);
			}
		}
		return 1;
	}
	return 0;
}

# Layout of BGP notification messages (RFC1771):
#
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | Error code    | Error subcode |           Data                |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
sub receive_notification {
	my $neighbor = shift;
	my ($buff, $bgprouterj) = @_;

	my $ip = $neighbor->get_ipaddress ();
	$neighbor->log (4, 4, "in receive_bgp_notification_message");
	my $errorcode = unpack("C", substr($buff,0,1));
	my $errorsubcode = unpack("C", substr($buff,1,1));
	my $errordata = "";
	if (length($buff) > 2) {
		$errordata = substr ($buff, 2, length($buff)-2);
	}
	$neighbor->log (4, 64,
		get_notification_string ($errorcode,$errorsubcode,$errordata));
	return ($errorcode, $errorsubcode, $errordata);
}

sub send_notification {
	my $neighbor = shift;
	my ($errorcode, $errorsubcode, $buff) = @_;

	if (!defined $errorsubcode) {
		$errorsubcode = 0;
	}
	my $data = pack ('C C', $errorcode, $errorsubcode);
	if (defined ($buff)) {
		$data .= $buff;
	}
	$neighbor->log (4, 64,
		get_notification_string ($errorcode,$errorsubcode,$buff));
	return $neighbor->send (BGP_NOTIFICATION, $data);
}

sub get_notification_string {
	my ($errorcode, $errorsubcode, $errordata) = @_;

	my $message = "Errorcode: $errorcode -> ";
	if ($errorcode < 1) {
		$message .= "Undefined ";
	}
	if ($errorcode >= 1) {
		$message .= BGP_ERRORCODE -> [$errorcode];
		if (defined $errorsubcode && $errorsubcode > 0) {
			$message .=  "-> " . BGP_ERRORSUBCODE->[$errorcode][$errorsubcode];
		}
		if (defined $errordata && length $errordata > 0) {
			$message .= " Errordata: " . length($errordata) . " bytes " .
				join (' ', unpack ('C*', $errordata));
		}
	}
	return $message;
}

sub set_state {
	my $neighbor = shift;
	my $state = shift;

	return $$neighbor{state} = $state;
}

sub get_state {
	my $neighbor = shift;

	return $$neighbor{state};
}

sub get_version {
	my $neighbor = shift;

	return $$neighbor{version};
}

sub set_version {
	my $neighbor = shift;
	my $version = shift;

	return $$neighbor{version} = $version;
}

sub get_routerid {
	my $neighbor = shift;

	return $$neighbor{routerid};
}

sub set_routerid {
	my $neighbor = shift;
	my $id = shift;

	return $$neighbor{routerid} = $id;
}

sub set_ipaddress {
	my $neighbor = shift;
	my $ip = shift;

	return $$neighbor{ip} = $ip;
}

sub get_ipaddress {
	my $neighbor = shift;

	return $$neighbor{ip};
}

sub set_as {
	my $neighbor = shift;
	my $as = shift;

	return $$neighbor{as} = $as;
}

sub get_as {
	my $neighbor = shift;

	return $$neighbor{as};
}

sub clear_routesin {
	my $neighbor = shift;

	return $$neighbor{routes_in} = 0;
}

sub get_routesin {
	my $neighbor = shift;

	return $$neighbor{routes_in};
}

sub increase_routesin {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (!defined $$neighbor{routes_in}) {
		return $$neighbor{routes_in} = $value;
	} else {
		return $$neighbor{routes_in} += $value;
	}
}

sub decrease_routesin {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (!defined $$neighbor{routes_in}) {
		return $$neighbor{routes_in} = 0;
	} else {
		if ($$neighbor{routes_in} < $value) {
			$$neighbor{routes_in} = 0;
			return;
		} else {
			return $$neighbor{routes_in} -= $value;
		}
	}
}

sub clear_routesout {
	my $neighbor = shift;

	return $$neighbor{routes_out} = 0;
}

sub get_routesout {
	my $neighbor = shift;

	return $$neighbor{routes_out};
}

sub increase_routesout {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (!defined $$neighbor{routes_out}) {
		return $$neighbor{routes_out} = $value;
	} else {
		return $$neighbor{routes_out} += $value;
	}
}

sub decrease_routesout {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (!defined $$neighbor{routes_out}) {
		return $$neighbor{routes_out} = 0;
	} else {
		if ($$neighbor{routes_out} < $value) {
			$$neighbor{routes_out} = 0;
			return;
		} else {
			return $$neighbor{routes_out} -= $value;
		}
	}
}

sub clear_routescurrent {
	my $neighbor = shift;

	return $$neighbor{routes_current} = 0;
}

sub get_routescurrent {
	my $neighbor = shift;

	return $$neighbor{routes_current};
}

sub increase_routescurrent {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (!defined $$neighbor{routes_current}) {
		return $$neighbor{routes_current} = $value;
	} else {
		return $$neighbor{routes_current} += $value;
	}
}

sub decrease_routescurrent {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (!defined $$neighbor{routes_current}) {
		return $$neighbor{routes_current} = 0;
	} else {
		if ($$neighbor{routes_current} < $value) {
			$$neighbor{routes_current} = 0;
			return;
		} else {
			return $$neighbor{routes_current} -= $value;
		}
	}
}

sub clear_history {
	my $neighbor = shift;

	@{$$neighbor{history}} = ();
	return 1;
}

sub add_history {
	my $neighbor = shift;
	my $event = shift;

	push @{$$neighbor{history}}, { 'time' => time(), 'event' => $event};
	return $#{$$neighbor{history}};
}

sub get_history {
	my $neighbor = shift;

	if (defined $$neighbor{history}) {
		return (@{$$neighbor{history}});
	} else {
		return ();
	}
}

sub get_history_detail {
	my $neighbor = shift;
	my $histref = shift;

	return ($$histref{time}, $$histref{event});
}

sub set_nexthop {
	my $neighbor = shift;
	my $nexthop = shift;

	return $$neighbor{nexthop} = $nexthop;
}

sub clear_nexthop {
	my $neighbor = shift;

	delete $$neighbor{nexthop};
}

sub get_nexthop {
	my $neighbor = shift;

	return $$neighbor{nexthop};
}

sub set_filehandle {
	my $neighbor = shift;
	my $fh = shift;

	return $$neighbor{filehandle} = $fh;
}

sub clear_filehandle {
	my $neighbor = shift;

	if (defined $$neighbor{filehandle}) {
		delete $$neighbor{filehandle};
	}
}

sub get_filehandle {
	my $neighbor = shift;

	return $$neighbor{filehandle};
}

sub set_time {
	my $neighbor = shift;

	return $$neighbor{time} = time();
}

sub get_time {
	my $neighbor = shift;

	return $$neighbor{time};
}

sub get_holdtime {
	my $neighbor = shift;

	return $$neighbor{holdtime};
}

sub clear_holdtime {
	my $neighbor = shift;

	delete $$neighbor{holdtime};
}

sub set_holdtime {
	my $neighbor = shift;
	my $value = shift;

	return $$neighbor{holdtime} = $value;
}

sub get_timer_keepaliveout {
	my $neighbor = shift;

	return $$neighbor{keepalive_out};
}

sub clear_timer_keepaliveout {
	my $neighbor = shift;

	delete $$neighbor{keepalive_out};
}

sub set_timer_keepaliveout {
	my $neighbor = shift;
	my $value = shift;

	return $$neighbor{keepalive_out} = $value;
}

sub get_timer_keepalivein {
	my $neighbor = shift;

	return $$neighbor{keepalive_in};
}

sub clear_timer_keepalivein {
	my $neighbor = shift;

	delete $$neighbor{keepalive_in};
}

sub set_timer_keepalivein {
	my $neighbor = shift;
	my $value = shift;

	return $$neighbor{keepalive_in} = $value;
}

sub set_authmethod {
	my $neighbor = shift;
	my $method = shift;

	return $$neighbor{authmethod} = $method;
}

sub get_authmethod {
	my $neighbor = shift;

	return $$neighbor{authmethod};
}

sub clear_authmethod {
	my $neighbor = shift;

	delete $$neighbor{authmethod};
}

sub clear_multiprotocol {
	my $neighbor = shift;
	my ($afi, $safi) = @_;

	if (defined $afi) {
		if (defined $safi) {
			if (defined $$neighbor{multi_protocol}{$afi}{$safi}) {
				delete $$neighbor{multi_protocol}{$afi}{$safi};
			}
			if (keys %{$$neighbor{multi_protocol}{$afi}} == 0) {
				delete $$neighbor{multi_protocol}{$afi};
			}
		} else {
			if (defined $$neighbor{multi_protocol}{$afi}) {
				delete $$neighbor{multi_protocol}{$afi};
			}
		}
	} else {
		if (defined $$neighbor{multi_protocol}) {
			delete $$neighbor{multi_protocol};
		}
	}
	return;
}

sub set_multiprotocol {
	my $neighbor = shift;
	my ($afi, $safi) = @_;

	if (!defined $afi || !defined $safi) {
		return;
	}
	return $$neighbor{multi_protocol}{$afi}{$safi} = 1;
}

sub get_multiprotocol_afi {
	my $neighbor = shift;

	if (defined $$neighbor{multi_protocol}) {
		return (keys %{$$neighbor{multi_protocol}});
	} else {
		return;
	}
}

sub get_multiprotocol_safi {
	my $neighbor = shift;
	my $afi = shift;

	if (defined $$neighbor{multi_protocol}{$afi}) {
		return (keys %{$$neighbor{multi_protocol}{$afi}});
	} else {
		return;
	}
}

sub routerefresh_enabled {
	my $neighbor = shift;
	my $value = shift;

	if (defined $value) {
		if ($value == 0) {
			if (defined $$neighbor{routefresh}) {
				delete $$neighbor{routerefresh};
			}
			return;
		} else {
			return $$neighbor{routerefresh} = 1;
		}
	} else {
		return defined $$neighbor{routerefresh} && $$neighbor{routerefresh}==1;
	}
}

sub routeserver_enabled {
	my $neighbor = shift;
	my ($version, $cluster_id) = @_;

	if (defined $version) {
		if ($version == 0) {
			if (defined $$neighbor{routeserver}) {
				delete $$neighbor{routeserver};
			}
			return;
		} else {
			$$neighbor{version} = $version;
			$$neighbor{cluster_id} = $cluster_id;
			return $$neighbor{support} = 1;
		}
	} else {
		if (!defined $$neighbor{routeserver}{version} ||
				!defined $$neighbor{routeserver}{cluster_id}) {
			return (undef, undef);
		} else {
		return ($$neighbor{routereserver}{version},
			$$neighbor{routeserver}{cluster_id});
		}
	}
}

sub get_localRIBentries {
	my $neighbor = shift;

	if (defined $$neighbor{localRIBentries}) {
		return $$neighbor{localRIBentries};
	} else {
		return 0;
	}
}

sub increase_localRIBentries {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (defined $$neighbor{localRIBentries}) {
		return $$neighbor{localRIBentries} += $value;
	} else {
		return $$neighbor{localRIBentries} = $value;
	}
}

sub decrease_localRIBentries {
	my $neighbor = shift;
	my $value = shift;

	defined $value || ($value = 1);

	if (defined $$neighbor{localRIBentries} && $$neighbor{localRIBentries}>0) {
		return $$neighbor{localRIBentries} -= $value;
	} else {
		return $$neighbor{localRIBentries} = 0;
	}
}

sub clear_localRIBentries {
	my $neighbor = shift;

	delete $$neighbor{localRIBentries};
}

sub unpack_prefix {
	my ($buff) = @_;

	my $prefix_length = unpack ('C', substr($buff, 0, 1));
	my $octets = int(($prefix_length + 7) / 8);
	my @ip = (0,0,0,0);
	if ($octets >= 1) {
		$ip[0] = unpack ('C', substr($buff, 1, 1));
	}
	if ($octets >= 2) {
		$ip[1] = unpack ('C', substr($buff, 2, 1));
	}
	if ($octets >= 3) {
		$ip[2] = unpack ('C', substr($buff, 3, 1));
	}
	if ($octets == 4) {
		$ip[3] = unpack ('C', substr($buff, 4, 1));
	}
	my $prefix = pack ('N', ($ip[0]<<24)+($ip[1]<<16)+($ip[2]<<8)+$ip[3]);
	return ($prefix_length, $prefix, $octets);
}

sub set_log_filehandle {
	my $neighbor = shift;

	my ($fh, @debug) = @_;

	return $$neighbor{loghandle} = $fh;
}

sub get_log_filehandle {
	my $neighbor = shift;

	return $$neighbor{loghandle};
}

sub set_loglevel {
	my $neighbor = shift;

	my ($type, $level) = @_;

	return $$neighbor{log}{$type} = $level;
}

sub get_loglevel {
	my $neighbor = shift;

	my $type = shift;

	return $$neighbor{log}{$type};
}

sub log {
	my $neighbor = shift;

	my ($type, $priority, @msgs) = @_;

	my $loglevel = $neighbor->{log}{$type};

	return if $priority > 2 && (!defined($loglevel) || $priority > $loglevel);

	my ($fh) = $neighbor->get_log_filehandle ();

	my $message = "";
	$message = strftime ("%D %T", localtime (time));
	$message .= sprintf(" %03s/%03s BGP: %15s ", $type, $priority,
		$neighbor->get_ipaddress());
	$message .= join (' ', @msgs);

	return if (!defined $fh && $priority > 2);

	if ($priority <= 2 || (defined ($loglevel) && $priority <= $loglevel) ) {
		my $message = "";
		if (defined $fh) {
			$message = strftime ("%D %T", localtime (time));
		}
		$message .= sprintf(" %03s/%03s BGP: %15s ", $type, $priority,
			$neighbor->get_ipaddress());

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
