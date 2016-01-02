# Constants.pm - define BGP protocol constants
# Copyright (C) 2002 Steven Hessing 
# steven@xs4all.nl

# This software is distributed under the terms of the license described in the
# file `LICENSE'. If this file is not included in the distribution then
# please contact the author of this software.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package BGP::Constants;
require Exporter;
@ISA = (Exporter);

@EXPORT = qw(
        BGP_VERSION BGP_MARKER BGP_OPEN BGP_UPDATE
        BGP_NOTIFICATION BGP_KEEPALIVE BGP_ROUTE_REFRESH BGP_LIST
        BGP_OPEN_Authentication BGP_OPEN_Capabilities_Advertisement
        BGP_OPEN_Route_Server BGP_OPEN_Route_Server01 BGP_OPEN_Capability_MP
        BGP_OPEN_Capability_Route_Refresh BGP_OPEN_Capability_Route_Refresh01
        MP_AFI_IPv4 MP_AFI_IPv6
        BGP_MP_SAFI_unicast BGP_MP_SAFI_multicast BGP_MP_SAFI_allcast
        BGP_UPDATE_Path_Attribute_OPTIONAL BGP_UPDATE_Path_Attribute_TRANSITIVE
        BGP_UPDATE_Path_Attribute_PARTIAL
        BGP_UPDATE_Path_Attribute_EXTENDED_LENGTH
        BGP_UPDATE_Path_Attribute_ORIGIN BGP_UPDATE_Path_Attribute_AS_PATH
        BGP_UPDATE_Path_Attribute_NEXT_HOP
        BGP_UPDATE_Path_Attribute_MULTI_EXIT_DISC
        BGP_UPDATE_Path_Attribute_LOCAL_PREF
        BGP_UPDATE_Path_Attribute_ATOMIC_AGGREGATE
        BGP_UPDATE_Path_Attribute_AGGREGATOR
        BGP_UPDATE_Path_Attribute_COMMUNITIES
        BGP_UPDATE_Path_Attribute_ORIGINATOR_ID
        BGP_UPDATE_Path_Attribute_CLUSTER_LIST
        BGP_UPDATE_Path_Attribute_DPA BGP_UPDATE_Path_Attribute_ADVERTISER
        BGP_UPDATE_Path_Attribute_CLUSTER_ID
        BGP_UPDATE_Path_Attribute_MP_REACH_NLRI
        BGP_UPDATE_Path_Attribute_MP_UNREACH_NLRI
        BGP_UPDATE_Path_Attribute_EXTENDED_COMMUNITIES
        BGP_UPDATE_Path_Attribute_ORIGIN_IGP
        BGP_UPDATE_Path_Attribute_ORIGIN_EGP
        BGP_UPDATE_Path_Attribute_ORIGIN_INCOMPLETE
        BGP_UPDATE_Path_Attribute_AS_PATH_AS_SET
        BGP_UPDATE_Path_Attribute_AS_PATH_AS_SEQUENCE
        BGP_UPDATE_Path_Attribute_AS_PATH_AS_CONFED_SET
        BGP_UPDATE_Path_Attribute_AS_PATH_AS_CONFED_SEQUENCE
        BGP_Path_Attribute_Flags_OPTIONAL BGP_Path_Attribute_Flags_TRANSITIVE
        BGP_Path_Attribute_Flags_PARTIAL
        BGP_ERRC_Message_Header_Error BGP_ERRC_OPEN_Message_Error
        BGP_ERRC_UPDATE_Message_Error BGP_ERRC_Hold_Timer_Expired
        BGP_ERRC_Finite_State_Machine_Error BGP_ERRC_Cease
        BGP_ERRSC_Connection_Not_Synchronized BGP_ERRSC_Bad_Message_Length
        BGP_ERRSC_Bad_Message_Type BGP_ERRSC_Unsupported_Version_Number
        BGP_ERRSC_Bad_Peer_AS BGP_ERRSC_Bad_BGP_Identifier
        BGP_ERRSC_Unsupported_Optional_Parameters
        BGP_ERRSC_Authentication_Failure BGP_ERRSC_Unacceptable_Hold_Time
        BGP_ERRSC_Unsupported_Capability BGP_ERRSC_Malformed_Attribute_List
        BGP_ERRSC_Unrecognized_Well_Known_Attribute
        BGP_ERRSC_Missing_Well_Known_Attribute BGP_ERRSC_Attribute_Flags_Error
        BGP_ERRSC_Attribute_Length_Error BGP_ERRSC_Invalid_ORIGIN_Attribute
        BGP_ERRSC_AS_Routing_Loop BGP_ERRSC_Invalid_NEXT_HOP_Attribute
        BGP_ERRSC_Optional_Attribute_Error BGP_ERRSC_Invalid_Network_Field
        BGP_ERRSC_Malformed_AS_PATH
		BGP_MESSAGE BGP_PATH_ATTRIBUTE BGP_ORIGIN BGP_AS_PATH
		BGP_ERRORCODE BGP_ERRORSUBCODE
		BGP_NEIGHBOR_IDLE BGP_NEIGHBOR_CONNECT BGP_NEIGHBOR_ACTIVE
		BGP_NEIGHBOR_OPENSENT BGP_NEIGHBOR_OPENCONFIRM BGP_NEIGHBOR_ESTABLISHED
		BGP_NEIGHBOR_STATUS
);

use constant BGP_VERSION => 4;
use constant BGP_MARKER =>
	pack ('NNNN', 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);

use constant BGP_OPEN => 1;
use constant BGP_UPDATE => 2;
use constant BGP_NOTIFICATION => 3;
use constant BGP_KEEPALIVE => 4;
use constant BGP_ROUTE_REFRESH => 5;
use constant BGP_LIST => 255;
use constant BGP_MESSAGE	=> [ "", "OPEN", "UPDATE", "NOTIFICATION",
			"KEEPALIVE", "ROUTE_REFRESH", "LIST"];

use constant BGP_OPEN_Authentication => 1;
use constant BGP_OPEN_Capabilities_Advertisement => 2;
use constant BGP_OPEN_Route_Server => 3;
use constant BGP_OPEN_Route_Server01 => 255;
use constant BGP_OPEN_Capability_MP => 1;
use constant BGP_OPEN_Capability_Route_Refresh => 2;
use constant BGP_OPEN_Capability_Route_Refresh01 => 128;
use constant MP_AFI_IPv4 => 1;
use constant MP_AFI_IPv6 => 2;
use constant BGP_MP_SAFI_unicast => 1;
use constant BGP_MP_SAFI_multicast => 2;
use constant BGP_MP_SAFI_allcast => 3;
use constant BGP_UPDATE_Path_Attribute_OPTIONAL => 2 << 6;
use constant BGP_UPDATE_Path_Attribute_TRANSITIVE => 2 << 5;
use constant BGP_UPDATE_Path_Attribute_PARTIAL => 2 << 4;
use constant BGP_UPDATE_Path_Attribute_EXTENDED_LENGTH => 2 << 3;
use constant BGP_UPDATE_Path_Attribute_ORIGIN => 1;
use constant BGP_UPDATE_Path_Attribute_AS_PATH => 2;
use constant BGP_UPDATE_Path_Attribute_NEXT_HOP => 3;
use constant BGP_UPDATE_Path_Attribute_MULTI_EXIT_DISC => 4;
use constant BGP_UPDATE_Path_Attribute_LOCAL_PREF => 5;
use constant BGP_UPDATE_Path_Attribute_ATOMIC_AGGREGATE => 6;
use constant BGP_UPDATE_Path_Attribute_AGGREGATOR => 7;
use constant BGP_UPDATE_Path_Attribute_COMMUNITIES => 8;
use constant BGP_UPDATE_Path_Attribute_ORIGINATOR_ID => 9;
use constant BGP_UPDATE_Path_Attribute_CLUSTER_LIST => 10;
use constant BGP_UPDATE_Path_Attribute_DPA => 11;
use constant BGP_UPDATE_Path_Attribute_ADVERTISER => 12;
use constant BGP_UPDATE_Path_Attribute_RCID_PATH => 13;
use constant BGP_UPDATE_Path_Attribute_MP_REACH_NLRI => 14;
use constant BGP_UPDATE_Path_Attribute_MP_UNREACH_NLRI => 15;
use constant BGP_UPDATE_Path_Attribute_EXTENDED_COMMUNITIES => 16;
use constant BGP_Path_Attribute => [ "", "ORIGIN", "AS PATH", "NEXT HOP",
			"MULTI EXIT DISC", "LOCAL PREFERENCE", "ATOMIC AGGREGATE", 
			"AGGREGATOR", "COMMUNITIES", "ORIGINATOR ID", "CLUSTER LIST",
			"DPA", "ADVERTISER", "RCID_PATH",
			"MP REACH NLRI", "MP UNREACH NLRI"];

use constant BGP_UPDATE_Path_Attribute_ORIGIN_IGP => 0;
use constant BGP_UPDATE_Path_Attribute_ORIGIN_EGP => 1;
use constant BGP_UPDATE_Path_Attribute_ORIGIN_INCOMPLETE => 2;
use constant BGP_ORIGIN => [ "IGP", "EGP", "IMCOMPLETE" ];

use constant BGP_UPDATE_Path_Attribute_AS_PATH_AS_SET => 1;
use constant BGP_UPDATE_Path_Attribute_AS_PATH_AS_SEQUENCE => 2;
use constant BGP_UPDATE_Path_Attribute_AS_PATH_AS_CONFED_SET => 3;
use constant BGP_UPDATE_Path_Attribute_AS_PATH_AS_CONFED_SEQUENCE => 4;
use constant BGP_AS_PATH => [ "", "AS SET", "AS SEQUENCE", "AS CONFED SET",
				"AS CONFED SEQUENCE" ];

use constant BGP_Path_Attribute_Flags_OPTIONAL => 128;
use constant BGP_Path_Attribute_Flags_TRANSITIVE => 64;
use constant BGP_Path_Attribute_Flags_PARTIAL => 32;
use constant BGP_ERRC_Message_Header_Error => 1;
use constant BGP_ERRC_OPEN_Message_Error => 2;
use constant BGP_ERRC_UPDATE_Message_Error => 3;
use constant BGP_ERRC_Hold_Timer_Expired => 4;
use constant BGP_ERRC_Finite_State_Machine_Error => 5;
use constant BGP_ERRC_Cease => 6;
use constant BGP_ERRORCODE => ["", "Message Header Error", "Open Message Error",
			"UPDATE Message Error", "Hold timer expired", "FSM Error", "Cease"];

use constant BGP_ERRSC_Connection_Not_Synchronized => 1;
use constant BGP_ERRSC_Bad_Message_Length => 2;
use constant BGP_ERRSC_Bad_Message_Type => 3;
use constant BGP_ERRSC_Unsupported_Version_Number => 1;
use constant BGP_ERRSC_Bad_Peer_AS => 2;
use constant BGP_ERRSC_Bad_BGP_Identifier => 3;
use constant BGP_ERRSC_Unsupported_Optional_Parameters => 4;
use constant BGP_ERRSC_Authentication_Failure => 5;
use constant BGP_ERRSC_Unacceptable_Hold_Time => 6;
use constant BGP_ERRSC_Unsupported_Capability => 7;
use constant BGP_ERRSC_Malformed_Attribute_List => 1;
use constant BGP_ERRSC_Unrecognized_Well_Known_Attribute => 2;
use constant BGP_ERRSC_Missing_Well_Known_Attribute => 3;
use constant BGP_ERRSC_Attribute_Flags_Error => 4;
use constant BGP_ERRSC_Attribute_Length_Error => 5;
use constant BGP_ERRSC_Invalid_ORIGIN_Attribute => 6;
use constant BGP_ERRSC_AS_Routing_Loop => 7;
use constant BGP_ERRSC_Invalid_NEXT_HOP_Attribute => 8;
use constant BGP_ERRSC_Optional_Attribute_Error => 9;
use constant BGP_ERRSC_Invalid_Network_Field => 10;
use constant BGP_ERRSC_Malformed_AS_PATH => 11;

use constant BGP_ERRORSUBCODE => [
		[],
		["", "Connection not synchronized", "Bad message length",
			"Bad message type"],
		["", "Unsupported version number", "Bad peer AS", "Bad BGP identifier",
			"Unsupported optional parameters", "Authentication failure",
			"Unacceptable hold time", "Unsupported capability"],
		["", "Malformed attribute list", "Unrecognized well-known attribute",
			"Missing well-known attribute", "Attribute flags error",
			"Attribute length error", "Invalid ORIGIN attribute",
			"AS routing loop", "Invalid NEXT-HOP attribute", 
			"Optional attribute error", "Invalid network field",
			"Malformed AS Path"]
];

use constant BGP_NEIGHBOR_IDLE => 1;
use constant BGP_NEIGHBOR_CONNECT => 2;
use constant BGP_NEIGHBOR_ACTIVE => 3;
use constant BGP_NEIGHBOR_OPENSENT => 4;
use constant BGP_NEIGHBOR_OPENCONFIRM => 5;
use constant BGP_NEIGHBOR_ESTABLISHED => 6;
use constant BGP_NEIGHBOR_STATUS => [ "", "Idle", "Connect", "Active",
			"OpenSent", "OpenConfirm", "Established"];

use constant BGP_LOG_OPEN => 1;
use constant BGP_LOG_UPDATE => 2;
use constant BGP_LOG_NOTIFICATION => 4;
use constant BGP_LOG_KEEPALIVE => 8;
use constant BGP_LOG_ROUTE_REFRESH => 16;
use constant BGP_LOG_LIST => 32;
use constant BGP_LOG_HEADER => 64;
use constant BGP_LOG_GENERAL => 128;
use constant BGP_LOG_LOCALRIB => 256;

#use constant BGP_LOG_TYPES => {
#	"OPEN" => 1,
#	"UPDATE" => 2,
#	"NOTIFICATION" => 4,
#	"KEEPALIVE" => 8,
#	"ROUTE-REFRESH" => 16,
#	"LIST" => 32,
#	"HEADER" => 64,
#	"GENERAL" => 128,
#	"LOCALRIB" => 256
#};

use constant BGP_LOG_CRITICAL => 1;
use constant BGP_LOG_WARNING => 2;
use constant BGP_LOG_INFO => 4;
use constant BGP_LOG_PARSE => 8;
use constant BGP_LOG_SESSION_ERRORS => 16;
use constant BGP_LOG_SESSION_WARNINGS => 32;
use constant BGP_LOG_PARSE_OPEN => 64;
use constant BGP_LOG_PARSE_OPEN_OPTIONAL => 128;
use constant BGP_LOG_PARSE_UPDATE => 64;
use constant BGP_LOG_PARSE_UPDATE_PREFIX => 128;
use constant BGP_LOG_PARSE_UPDATE_PATH_ATTRIBUTES => 256;
use constant BGP_LOG_PARSE_NOTIFICATION => 64;
use constant BGP_LOG_PARSE_REFRESH => 64;
use constant BGP_LOG_SESSION_PARSE => 64;
use constant BGP_LOG_LOCALRIB_CHANGES => 64;
use constant BGP_LOG_LOCALRIB_CHANGES_ROUTES => 128;
use constant BGP_LOG_LOCALRIB_CHANGES_EVAL => 256;

#use constant BGP_LOG_LEVELS => {
#	"CRITICAL" => 1,
#	"WARNING" => 2,
#	"INFO" => 4,
#	"PARSE" => 8,
#	"SESSION-ERRORS" => 16,
#	"SESSION-WARNINGS" => 32,
#	"PARSE-OPEN" => 64,
#	"PARSE-OPEN-OPTIONAL" => 128,
#	"PARSE-UPDATE" => 64,
#	"PARSE-UPDATE-PREFIX" => 128,
#	"PARSE-UPDATE-PATH-ATTRIBUTRES" => 256,
#	"PARSE-NOTIFICATION" => 64,
#	"PARSE-REFRESH" => 64,
#	"SESSION-PARSE" => 64,
#	"LOCALRIB-CHANGES" => 64,
#	"LOCALRIB-CHANGES-ROUTES" => 128,
#	"LOCALRIB-CHANGES-EVAL" => 256
#};
