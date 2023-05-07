#pragma once
#include "Global.h"

#define ETHERNET_HEADER_LENGTH 14
#define ARP_HEADER_LENGTH 28
#define IPV4_BASE_HEADER_LENGTH 20
#define IPV6_BASE_HEADER_LENGTH 40
#define UDP_HEADER_LENGTH 8
#define TCP_BASE_HEADER_LENGTH 20
#define ICMP_BASE_HEADER_LENGTH 8

#define ETHERNET_TYPE_IPv4 0x0800
#define ETHERNET_TYPE_IPv6 0x86DD
#define ETHERNET_TYPE_ARP 0x0806

#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

#define PORT_DNS 53
#define PORT_DHCP_CLIENT 67
#define PORT_DHCP_SERVER 68
#define PORT_HTTP 80

#define TLS_CHANGECIPHERSPEC 20
#define TLS_ALERT 21
#define TLS_HANDSHAKE 22
#define TLS_APPLICATIONDATA 23
#define TLS_HEARTBEAT 24


typedef struct Ethernet_Header
{
	u_char	destination[6];
	u_char	source[6];
	u_short	type;

} Ethernet_Header;

typedef struct ARP_Header
{
	u_short hardware_type;
	u_short protocol_type;
	u_char hardware_size;
	u_char protocol_size;
	u_short opcode;
	u_char source_hardware_addr[6];
	u_char source_ip_addr[4];
	u_char destination_hardware_addr[6];
	u_char destination_ip_addr[4];
}ARP_Header;

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

typedef struct ICMP_Header
{
	u_short type;
	u_short checksum;
	u_int other;
}ICMP_Header;