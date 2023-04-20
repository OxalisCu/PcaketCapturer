#pragma once
#include "Global.h"

#define ETHERNET_HEADER_LENGTH 14
#define IPV4_BASE_HEADER_LENGTH 20
#define IPV6_BASE_HEADER_LENGTH 40
#define UDP_HEADER_LENGTH 8
#define TCP_BASE_HEADER_LENGTH 20
#define DNS_HEADER_LENGTH 12

#define ETHERNET_TYPE_IPv4 0x0800
#define ETHERNET_TYPE_IPv6 0x86DD
#define ETHERNET_TYPE_ARP 0x0806

#define PROTOCOL_ICMP 1
#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17

#define PORT_DNS 53
#define PORT_DHCP_CLIENT 67
#define PORT_DHCP_SERVER 68
#define PORT_HTTP 80

typedef struct Ethernet_Header
{
	u_char	destination[6];
	u_char	source[6];
	u_short	type;

} Ethernet_Header;

typedef struct IPv4_Header
{
	u_char version_headerlength;
	u_char differentiated_services;
	u_short total_length;
	u_short	identification;
	u_short	flags_fragmentoffset;
	u_char time_to_live;
	u_char protocol;
	u_short	header_checksum;
	u_char source[4];
	u_char destination[4];
}IPv4_Header;

typedef struct IPv6_Header
{
	u_int version_traffic_flow;
	u_short payload_length;
	u_char next_header;
	u_char hop_limit;
	u_short source[8];
	u_short destination[8];
}IPv6_Header;

typedef struct UDP_Header
{
	u_short source_port;
	u_short destination_port;
	u_short length;
	u_short checksum;
}UDP_Header;

typedef struct TCP_Header
{
	u_short source_port;
	u_short destination_port;
	u_int sequence_number;
	u_int acknowledge_number;
	u_short headerlength_flags;
	u_short window;
	u_short checksum;
	u_short urgent_pointer;
}TCP_Header;