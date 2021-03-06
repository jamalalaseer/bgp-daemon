# bgp-daemon
bgpd.pl - a bgp-daemon with additional example configs 
#

& traceiface.pl,v 1.1 2007/02/04 22:58:04 jtk Exp $

Two network tools
#
traceiface.pl - traceroute with extension to discover router egress hop address
#
and
#
bgpd.pl - a partial implementation of the BGP protocol (RFC1771) written in
perl. It has been designed as a module to be used in other applications 
and as tool to monitor BGP routing updates and collect all kinds of statistics.
#

Version 0.06.1+ - Minor changes by Jamal Al-Aseer 5/5/2015
Original Version 0.06 9/27/2002
Copyright (C)2002 Steven Hessing (steven@xs4all.nl)
See the file LICENSE for licensing details.
#

You might have to set a PERL environment using:
echo 'eval $(perl -I$HOME/perl5/lib/perl5 -Mlocal::lib)' >>~/.bashrc

bgpd.pl is a partial implementation of the BGP protocol (RFC1771) written in
perl. It has been designed as a module to be used in other applications 
and as tool to monitor BGP routing updates and collect all kinds of statistics.

bgpd.pl is NOT written to be used as a BGP router in an operational network,
in fact is has no support to propogate routing information because there is
no code to send BGP UPDATE messages. bgpd.pl also does not touch the routing
table of the host it runs on. 

This 0.06 release is a bug fix release. Please see the CHANGES file for details. 

LIMITATIONS:
With the constraints described in the above text, the software supports the
following RFCs to the extend indicated:
RFC1771 - Border Gateway Protocol version 4
  adj-RIB-out not maintained, no outgoing BGP UPDATE messages, BGP TCP sessions
  are not initiated. No Finite State Machine support.
RFC1863 - BGP Route Server
  Route Server client behaviour is supported.
RFC1997 - BGP Communities attribute
  supported
RFC2385 - Protection of BGP Sessions via the TCP MD5 Signature Option
  not supported
RFC2439 - BGP Route Flap Damping
  not supported, not needed because we don't send out UPDATES
RFC2545 - Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing
  not supported
RFC2547 - BGP/MPLS VPNs
  not supported
RFC2796 - BGP Route reflection
  supported
RFC2842 - Capabilities Advertisement with BGP-4
  We don't follow this RFC when a neighbor doesn't support a capability that
  we do. We keep announcing the same set of capabilities.
RFC2858 - Multiprotocol Extensions for BGP-4
  almost no support. We recognise the RFC2842-capability announcement
RFC2918 - Route refresh capability for BGP-4
  supported
RFC3065 - Autonomous System Confederations for BGP
  supported

The following RFC drafts are not yet supported:
draft-ietf-id-bgp4-12
draft-ietf-id-route-filter-03
draft-ietf-id-restart-00
draft-ietf-id-as4bytes-01
draft-ietf-id-route-oscillation-00

Multiprotocol support:
Although the MP capability is accepted and announced in the BGP OPEN message,
all MP path attributes in BGP UPDATE messages are silently ignored. There is
no support for the MPLS/BGP VPN application or IPv6. This is planned for
future releases.

DOWNLOAD:
bgpd.pl has its own project on sourceforge.net:
    http://sourceforge.net/projects/bgpd/

INSTALLATION:
- download and install Net::Patricia from
         http://net.doit.wisc.edu/~plonka/Net-Patricia/
- cd <parent-dir>; tar zxvf bgpd.pl-0.05.tar.gz

CONFIGURATION: 
There is a `bgpd.conf' configuration file. It accepts three types of commands:
  router bgp <as>                     # this is your own AS number
  router-id <a.b.c.d>                 # The ip address of your BGP router 
                                      # the default is the address retuned by
                                      # gethostbyname()
  neighbor <a.b.c.d> remote-as <as>   # IP address & AS of neighbor

USAGE:
- cd into the bgpd.pl-0.05 directory
- `su' to root
- ./bgpd.pl [--log [syslog|file|stdout] ] [ --daemon] 
		[ --config <config file> ]
- There are many logging levels, read the `LOGGING' file. If you enable full
  logging then prepare for a lot of logging information! For a full BGP table
  you'll get log file that will easily grow beyond 200MB
- set up a BGP session from your router to the host on which you run bgpd.pl
  If you use a private AS then don't forget to enable eBGP multihop on your
  router, if necessary. If you prefer to use iBGP then I would suggest
  configuring your router as a route reflector for this BGP connection.
- You can send the bgpd.pl process a USR1 signal to get a dump of the routing
  table or USR2 to get a dump of the state of the BGP neighbors
  
MAILING-LIST:
You can subscribe to bgpd-users-request@lists.sourceforge.net, put in the
body of the message the word `subscribe'

SECURITY CONSIDERATIONS:
- connecting this alpha-stage software which has undergone limited testing
  to your production network can result in considerable damage to your
  network! Use this software at your own risk!
- this software runs as root because it needs to connect to the TCP/BGP port.
  The code does not switch back to a regular UID yet. It opens a logfile
  for writing in the current working directory under the name bgpd.log. Make
  sure that this is not a (sym-) link!

INTEROPERABILITY:
- bgpd.pl has succesfully maintained BGP sessions with:
  - Zebra 0.91A
  - Cisco IOS ios 12.0(14)S2 running on a Cisco 7206
- It has not been tested yet with multiple BGP sessions. The local-RIB 
route selection has thus not been tested.
