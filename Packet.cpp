#include "Packet.h"
#include "Utils.h"

Packet::Packet(){}

Packet::Packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& num, StreamPool* ss)
{
	streams = ss;

	frame = {
		num,
		transTime(header->ts),
		NULL,
		NULL,
		0,
		0,
		NULL,
		header->len,
		NULL,
	};

	if (pkt_data != NULL && header != NULL)
	{
		this->pkt_data = (u_char*)malloc(header->len);
		memcpy(this->pkt_data, pkt_data, header->len);
		decodeEthernet(pkt_data);
	}
}

Packet::~Packet()
{
	for (auto p : protos)
	{
		clearProtos(p);
	}
}

void Packet::clearProtos(ProtoMsg* proto)
{
	if (proto->children.isEmpty())
	{
		delete proto;
		return;
	}
	for (auto p : proto->children)
	{
		clearProtos(p);
	}
	proto->children.clear();
}

void Packet::decodeEthernet(const u_char* payload)
{
	// obtain the ethernet msg
	Ethernet_Header* ethh = (Ethernet_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	MsgItem* destination = new MsgItem{
		"destination",
		MACAddr2String(ethh->destination),
		-1,
		offset,
		48
	};
	offset += 48;
	MsgItem* source = new MsgItem{
		"source",
		MACAddr2String(ethh->source),
		-1,
		offset,
		48
	};
	offset += 48;
	// judge upper protocol
	QString eth_type;
	switch (ntohs(ethh->type))
	{
	case ETHERNET_TYPE_IPv4:
		eth_type = "ipv4";
		decodeUpper = &Packet::decodeIPv4;
		break;
	case ETHERNET_TYPE_IPv6:
		decodeUpper = &Packet::decodeIPv6;
		eth_type = "ipv6";
		break;
	case ETHERNET_TYPE_ARP:
		eth_type = "arp";
		decodeUpper = &Packet::decodeARP;
		break;
	default:
		eth_type = "unkown ( 0x" + QString::asprintf("%04x", ntohs(ethh->type)) + " )";
		break;
	}
	MsgItem* type = new MsgItem{
		"type",
		eth_type,
		ntohs(ethh->type),
		offset,
		48
	};

	// add protocol item
	int hl = ETHERNET_HEADER_LENGTH;
	MsgItem* eth_msg = new MsgItem;
	eth_msg->name = "ethernet";
	eth_msg->offset = 0;
	eth_msg->length = hl * 8;
	// whether contains FCS or not
	//eth_msg->total_length = frame.length - eth_msg->offset - 4;
	eth_msg->children.push_back(destination);
	eth_msg->children.push_back(source);
	eth_msg->children.push_back(type);
	protos.push_back(eth_msg);
	// refresh frame msg
	frame.src_addr = source->desc;
	frame.des_addr = destination->desc;
	frame.protocol = "ethernet";
	frame.stream_index = -1;
	
	// decode the upper protocol
	payload += hl;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeARP(const u_char* payload)
{
	ARP_Header* arph = (ARP_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	MsgItem* hardware_type = new MsgItem{
		"hardware type",
		QString::number(ntohs(arph->hardware_type)),
		ntohs(arph->hardware_type),
		offset,
		16
	};
	offset += 16;
	MsgItem* protocol_type = new MsgItem{
		"protocol type",
		QString::number(ntohs(arph->protocol_type)),
		ntohs(arph->protocol_type),
		offset,
		16
	};
	offset += 16;
	MsgItem* hardware_size = new MsgItem{
		"hardware size",
		QString::number(arph->hardware_size),
		arph->hardware_size,
		offset,
		8
	};
	offset += 8;
	MsgItem* protocol_size = new MsgItem{
		"protocol size",
		QString::number(arph->protocol_size),
		arph->protocol_size,
		offset,
		8
	};
	offset += 8;
	MsgItem* opcode = new MsgItem{
		"opcode",
		QString::number(ntohs(arph->opcode)),
		ntohs(arph->protocol_size),
		offset,
		16
	};
	offset += 16;
	MsgItem* source_hardware_addr = new MsgItem{
		"source hardware address",
		MACAddr2String(arph->source_hardware_addr),
		-1,
		offset,
		48
	};
	offset += 48;
	MsgItem* source_ip_addr = new MsgItem{
		"source ip address",
		IPv4Addr2String(arph->source_ip_addr),
		-1,
		offset,
		32
	};
	offset += 32;
	MsgItem* destination_hardware_addr = new MsgItem{
		"destination hardware address",
		MACAddr2String(arph->destination_hardware_addr),
		-1,
		offset,
		48
	};
	offset += 48;
	MsgItem* destination_ip_addr = new MsgItem{
		"destination ip address",
		IPv4Addr2String(arph->destination_ip_addr),
		-1,
		offset,
		32
	};
	offset += 32;

	int hl = ARP_HEADER_LENGTH;
	MsgItem* arp_msg = new MsgItem;
	arp_msg->name = "arp";
	arp_msg->offset = protos.back()->offset + protos.back()->length;
	arp_msg->length = hl * 8;
	arp_msg->children.push_back(hardware_type);
	arp_msg->children.push_back(protocol_type);
	arp_msg->children.push_back(hardware_size);
	arp_msg->children.push_back(hardware_size);
	arp_msg->children.push_back(opcode);
	arp_msg->children.push_back(source_hardware_addr);
	arp_msg->children.push_back(source_ip_addr);
	arp_msg->children.push_back(destination_hardware_addr);
	arp_msg->children.push_back(destination_ip_addr);
	protos.push_back(arp_msg);
	
	frame.protocol = "arp";
}

void Packet::decodeIPv4(const u_char* payload)
{
	// obtain the ipv4 msg
	IPv4_Header* ipv4h = (IPv4_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	MsgItem* version = new MsgItem{
		"version",
		QString::number((u_char)(ipv4h->version_headerlength & 0xf0) >> 4),
		(u_char)(ipv4h->version_headerlength & 0xf0) >> 4,
		offset,
		4
	};
	offset += 4;
	u_int headerlength = (ipv4h->version_headerlength & 0x0f) * 4;
	MsgItem* header_length = new MsgItem{
		"header length",
		QString::number(headerlength),
		(int)headerlength,
		offset,
		4
	};
	offset += 4;
	MsgItem* differentiated_services = new MsgItem{
		"differentiated services",
		QString::number(ipv4h->differentiated_services),
		ipv4h->differentiated_services,
		offset,
		8
	};
	offset += 8;
	MsgItem* total_length = new MsgItem{
		"total length",
		QString::number(ntohs(ipv4h->total_length)),
		ntohs(ipv4h->total_length),
		offset,
		16
	};
	offset += 16;
	MsgItem* identification = new MsgItem{
		"identification",
		QString::number(ntohs(ipv4h->identification)),
		ntohs(ipv4h->identification),
		offset,
		16
	};
	offset += 16;
	QString ipv4_flags;
	bool ipv4_reserved = ntohs(ipv4h->flags_fragmentoffset) & 0x8000;
	bool ipv4_df = ntohs(ipv4h->flags_fragmentoffset) & 0x4000;
	bool ipv4_mf = ntohs(ipv4h->flags_fragmentoffset) & 0x2000;
	if (ipv4_df)
	{
		ipv4_flags = "don't fragment";
	} 
	else if (!ipv4_df && ipv4_mf) {
		ipv4_flags = "more fragments";
	}
	else {
		ipv4_flags = "no more fragments";
	}
	MsgItem* flags = new MsgItem{
		"flags",
		ipv4_flags,
		-1,
		offset,
		3
	};
	flags->children.push_back(
		new MsgItem{
			"Reserved bit",
			ipv4_reserved ? "Set" : "Not Set",
			ipv4_reserved,
			0,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"Don't fragment",
			ipv4_df ? "Set" : "Not Set",
			ipv4_df,
			1,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"More fragments",
			ipv4_mf ? "Set" : "Not Set",
			ipv4_mf,
			2,
			1
		}
	);
	offset += 3;
	MsgItem* fragment_offset = new MsgItem{
		"fragment offset",
		QString::number((ntohs(ipv4h->flags_fragmentoffset) & 0xe000) >> 13),
		(ntohs(ipv4h->flags_fragmentoffset) & 0xe000) >> 13,
		offset,
		13
	};
	offset += 13;
	MsgItem* time_to_live = new MsgItem{
		"time to live",
		QString::number(ipv4h->time_to_live),
		ipv4h->time_to_live,
		offset,
		8
	};
	offset += 8;
	// judge upper protocol
	QString ipv4_protocol;
	switch (ipv4h->protocol)
	{
	case 1:
		ipv4_protocol = "ICMP";
		decodeUpper = &Packet::decodeICMP;
		break;
	case 2:
		ipv4_protocol = "IGMP";
		break;
	case 4:
		ipv4_protocol = "IPv4";
		decodeUpper = &Packet::decodeIPv4;
		break;
	case 6:
		ipv4_protocol = "TCP";
		decodeUpper = &Packet::decodeTCP;
		break;
	case 8:
		ipv4_protocol = "EGP";
		break;
	case 9:
		ipv4_protocol = "IGP";
		break;
	case 17:
		ipv4_protocol = "UDP";
		decodeUpper = &Packet::decodeUDP;
		break;
	case 41:
		ipv4_protocol = "IPv6";
		decodeUpper = &Packet::decodeIPv6;
		break;
	case 50:
		ipv4_protocol = "ESP";
		break;
	case 51:
		ipv4_protocol = "AH";
		break;
	default:
		ipv4_protocol = "Unknown(" + QString::number(ipv4h->protocol) + ")";
		break;
	}
	MsgItem* protocol = new MsgItem{
		"protocol",
		ipv4_protocol,
		ipv4h->protocol,
		offset,
		8
	};
	offset += 8;
	MsgItem* header_checksum = new MsgItem{
		"header checksum",
		QString::asprintf("0x%04x", ntohs(ipv4h->header_checksum)),
		-1,
		offset,
		16
	};
	offset += 16;
	MsgItem* source = new MsgItem{
		"source",
		IPv4Addr2String(ipv4h->source),
		-1,
		offset,
		32
	};
	offset += 32;
	MsgItem* destination = new MsgItem{
		"destination",
		IPv4Addr2String(ipv4h->destination),
		-1,
		offset,
		32
	};
	offset += 32;
	MsgItem* options = NULL;
	if (headerlength > IPV4_BASE_HEADER_LENGTH)
	{
		options = new MsgItem{
			"options",
			QString::number(headerlength - IPV4_BASE_HEADER_LENGTH) + "bytes",
			-1,
			offset,
			headerlength - IPV4_BASE_HEADER_LENGTH
		};
	}

	int hl = headerlength;
	MsgItem* ipv4_msg = new MsgItem;
	ipv4_msg->name = "ipv4";
	ipv4_msg->offset = protos.back()->offset + protos.back()->length;
	ipv4_msg->length = hl * 8;
	ipv4_msg->children.push_back(version);
	ipv4_msg->children.push_back(header_length);
	ipv4_msg->children.push_back(differentiated_services);
	ipv4_msg->children.push_back(total_length);
	ipv4_msg->children.push_back(identification);
	ipv4_msg->children.push_back(flags);
	ipv4_msg->children.push_back(fragment_offset);
	ipv4_msg->children.push_back(time_to_live);
	ipv4_msg->children.push_back(protocol);
	ipv4_msg->children.push_back(header_checksum);
	ipv4_msg->children.push_back(source);
	ipv4_msg->children.push_back(destination);
	if (options) ipv4_msg->children.push_back(options);

	protos.push_back(ipv4_msg);

	frame.src_addr = source->desc;
	frame.des_addr = destination->desc;
	frame.protocol = "ipv4";
	
	// decode upper protocol
	payload += hl;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeIPv6(const u_char* payload)
{
	IPv6_Header* ipv6h = (IPv6_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	MsgItem* version = new MsgItem{
		"version",
		QString::number((ntohi(ipv6h->version_traffic_flow) & 0xf0000000) >> 28),
		(int)((ntohi(ipv6h->version_traffic_flow & 0xf0000000)) >> 28),
		offset,
		4
	};
	offset += 4;
	MsgItem* traffic_class = new MsgItem{
		"traffic class",
		QString::asprintf("0x%02x", ntohi(ipv6h->version_traffic_flow & 0x0ff00000) >> 20),
		(int)(ntohi(ipv6h->version_traffic_flow & 0x0ff00000) >> 20),
		offset,
		8
	};
	offset += 8;
	MsgItem* flow_label = new MsgItem{
		"flow label",
		QString::asprintf("0x%05x", ntohi(ipv6h->version_traffic_flow) & 0x000fffff),
		(int)(ntohi(ipv6h->version_traffic_flow) & 0x000fffff),
		offset,
		20
	};
	offset += 20;
	MsgItem* payload_length = new MsgItem{
		"payload length",
		QString::number(ntohs(ipv6h->payload_length)) + "bytes",
		ntohs(ipv6h->payload_length),
		offset,
		16
	};
	offset += 16;
	QString nextheader;
	bool other = false;
	switch (ipv6h->next_header)
	{
	case 1:
		nextheader = "ICMP";
		decodeUpper = &Packet::decodeICMP;
		break;
	case 2:
		nextheader = "IGMP";
		break;
	case 6:
		nextheader = "TCP";
		decodeUpper = &Packet::decodeTCP;
		break;
	case 17:
		nextheader = "UDP";
		decodeUpper = &Packet::decodeUDP;
		break;
	default:
		nextheader = "other header(" + QString::number(ipv6h->next_header) + ")";
		other = true;
		break;
	}
	MsgItem* next_header = new MsgItem{
		"next header",
		nextheader,
		ipv6h->next_header,
		offset,
		8
	};
	offset += 8;
	MsgItem* hop_limit = new MsgItem{
		"hop limit",
		QString::number(ipv6h->hop_limit),
		ipv6h->hop_limit,
		offset,
		8
	};
	offset += 8;
	MsgItem* source = new MsgItem{
		"source",
		IPv6Addr2String(ipv6h->source),
		-1,
		offset,
		128
	};
	offset += 128;
	MsgItem* destination = new MsgItem{
		"destination",
		IPv6Addr2String(ipv6h->destination),
		-1,
		offset,
		128
	};
	offset += 128;
	// cann't deal with extension header now
	MsgItem* ext_headers = NULL;
	int ext_len = 0;

	int hl = IPV6_BASE_HEADER_LENGTH + ext_len;
	MsgItem* ipv6_msg = new MsgItem;
	ipv6_msg->name = "ipv6";
	ipv6_msg->offset = protos.back()->offset + protos.back()->length;
	ipv6_msg->length = hl * 8;
	ipv6_msg->children.push_back(version);
	ipv6_msg->children.push_back(traffic_class);
	ipv6_msg->children.push_back(flow_label);
	ipv6_msg->children.push_back(payload_length);
	ipv6_msg->children.push_back(next_header);
	ipv6_msg->children.push_back(hop_limit);
	ipv6_msg->children.push_back(source);
	ipv6_msg->children.push_back(destination);
	if (ext_headers) ipv6_msg->children.push_back(ext_headers);

	protos.push_back(ipv6_msg);

	frame.src_addr = source->desc;
	frame.des_addr = destination->desc;
	frame.protocol = "ipv6";

	payload += hl;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeICMP(const u_char* payload)
{
	ICMP_Header* icmph = (ICMP_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	QString type;
	switch (ntohs(icmph->type))
	{
	case 0x0000: 
		type = "echo reply";
		break;
	case 0x0300:
		type = "network unreachable";
		break;
	case 0x0301:
		type = "host unreachable";
		break;
	case 0x0302:
		type = "protocol unreachable";
		break;
	case 0x0303:
		type = "port unreachable";
		break;
	case 0x0304:
		type = "fragmentation needed but no flag bit set";
		break;
	case 0x0305:
		type = "source routing failed";
		break;
	case 0x0306:
		type = "destination network unknown";
		break;
	case 0x0307:
		type = "dsetination host unknown";
		break;
	case 0x0308:
		type = "source host isolated";
		break;
	case 0x0309:
		type = "destination network administratively prohibited";
		break;
	case 0x030a:
		type = "destination host administratively prohibited";
		break;
	case 0x030b:
		type = "network unreachable for TOS";
		break;
	case 0x030c:
		type = "host unreachable for TOS";
		break;
	case 0x030d:
		type = "communication administratively prohibited by filtering";
		break;
	case 0x030e:
		type = "host precedence violation";
		break;
	case 0x030f:
		type = "precedence cutoff in effect";
		break;
	case 0x0400:
		type = "source quench";
		break;
	case 0x0500:
		type = "redirect for network";
		break;
	case 0x0501:
		type = "redirect for host";
		break;
	case 0x0502:
		type = "redirect for TOS and network";
		break;
	case 0x0503:
		type = "redirect for TOS and host";
		break;
	case 0x0800:
		type = "echo request";
		break;
	case 0x0900:
		type = "router advertisement";
		break;
	case 0x0a00:
		type = "router solicitation";
		break;
	case 0x0b00:
		type = "TTL equals 0 during transit";
		break;
	case 0x0b01:
		type = "TTL equals 0 during reassembly";
		break;
	case 0x0c00:
		type = "IP header bad (catchall error)";
		break;
	case 0x0c01:
		type = "required options missing";
		break;
	case 0x0d00:
		type = "timestamp request (obsolete)";
		break;
	case 0x0e00:
		type = "timestamp reply (obsolete)";
		break;
	case 0x0f00:
		type = "information request (obsolete)";
		break;
	case 0x1000:
		type = "information reply (obsolete)";
		break;
	case 0x1100:
		type = "address mask request";
		break;
	}
	MsgItem* typecode = new MsgItem{
		"type",
		type,
		ntohs(icmph->type),
		offset,
		16,
	};
	offset += 16;
	MsgItem* checksum = new MsgItem{
		"checksum",
		QString::number(ntohs(icmph->checksum)),
		ntohs(icmph->checksum),
		offset,
		16,
	};
	offset += 16;
	MsgItem* other = new MsgItem{
		"other",
		QString::number(ntohi(icmph->other)),
		(int)(ntohi(icmph->other)),
		offset,
		32
	};

	int h1 = ICMP_BASE_HEADER_LENGTH;
	MsgItem* icmp_msg = new MsgItem;
	icmp_msg->name = "icmp";
	icmp_msg->offset = protos.back()->offset + protos.back()->length;
	icmp_msg->length = h1 * 8;
	icmp_msg->children.push_back(typecode);
	icmp_msg->children.push_back(checksum);
	icmp_msg->children.push_back(other);
	protos.push_back(icmp_msg);

	frame.protocol = "icmp";
}

void Packet::decodeUDP(const u_char* payload)
{
	UDP_Header* udph = (UDP_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	MsgItem* source_port = new MsgItem{
		"source port",
		QString::number(ntohs(udph->source_port)),
		ntohs(udph->source_port),
		offset,
		16
	};
	offset += 16;
	MsgItem* destination_port = new MsgItem{
		"destination port",
		QString::number(ntohs(udph->destination_port)),
		ntohs(udph->destination_port),
		offset,
		16
	};
	offset += 16;
	MsgItem* length = new MsgItem{
		"length",
		QString::number(ntohs(udph->length)),
		ntohs(udph->length),
		offset,
		16
	};
	offset += 16;
	MsgItem* checksum = new MsgItem{
		"checksum",
		QString::asprintf("%04x", ntohs(udph->checksum)),
		ntohs(udph->checksum),
		offset,
		16
	};
	offset += 16;

	int hl = UDP_HEADER_LENGTH;
	MsgItem* udp_msg = new MsgItem;
	udp_msg->name = "udp";
	udp_msg->offset = protos.back()->offset + protos.back()->length;
	udp_msg->length = hl * 8;
	udp_msg->children.push_back(source_port);
	udp_msg->children.push_back(destination_port);
	udp_msg->children.push_back(length);
	udp_msg->children.push_back(checksum);
	protos.push_back(udp_msg);

	frame.src_port = source_port->value;
	frame.des_port = destination_port->value;
	frame.protocol = "udp";

	// stream index
	StreamMsg* s = new StreamMsg{
		frame.src_addr,
		frame.des_addr,
		frame.src_port,
		frame.des_port,
		frame.protocol
	};
	int idx;
	if (!streams->hasStream(s))
	{
		idx = streams->addStream(s);
	}
	else {
		idx = streams->getStreamIndex(s);
	}
	frame.stream_index = idx;

	payload += hl;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeTCP(const u_char* payload)
{
	TCP_Header* tcph = (TCP_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	MsgItem* source_port = new MsgItem{
		"source port",
		QString::number(ntohs(tcph->source_port)),
		ntohs(tcph->source_port),
		offset,
		16
	};
	offset += 16;
	MsgItem* destination_port = new MsgItem{
		"destination port",
		QString::number(ntohs(tcph->destination_port)),
		ntohs(tcph->destination_port),
		offset,
		16
	};
	offset += 16;
	MsgItem* sequence_number = new MsgItem{
		"sequence number",
		QString::number(ntohi(tcph->sequence_number)),
		(int)ntohi(tcph->sequence_number),
		offset,
		32
	};
	offset += 32;
	MsgItem* acknowledge_number = new MsgItem{
		"acknowledge number",
		QString::number(ntohi(tcph->acknowledge_number)),
		(int)ntohi(tcph->acknowledge_number),
		offset,
		32
	};
	offset += 32;
	MsgItem* header_length = new MsgItem{
		"header length",
		QString::number((ntohs(tcph->headerlength_flags) >> 12) * 4),
		(ntohs(tcph->headerlength_flags) >> 12) * 4,
		offset,
		4
	};
	offset += 4;
	MsgItem* reserved = new MsgItem{
		"reserved bits",
		QString::number(ntohs(tcph->headerlength_flags) & 0x0fc),
		ntohs(tcph->headerlength_flags) & 0x0fc,
		offset,
		6
	};
	offset += 6;
	bool flags_urg = ntohs(tcph->headerlength_flags) & 0x0020;
	bool flags_ack = ntohs(tcph->headerlength_flags) & 0x0010;
	bool flags_psh = ntohs(tcph->headerlength_flags) & 0x0008;
	bool flags_rst = ntohs(tcph->headerlength_flags) & 0x0004;
	bool flags_syn = ntohs(tcph->headerlength_flags) & 0x0002;
	bool flags_fin = ntohs(tcph->headerlength_flags) & 0x0001;
	QString flagsstr;
	if (flags_urg) flagsstr += "URG ";
	if (flags_ack) flagsstr += "ACK ";
	if (flags_psh) flagsstr += "PSH ";
	if (flags_rst) flagsstr += "RST ";
	if (flags_syn) flagsstr += "SYN ";
	if (flags_fin) flagsstr += "FIN ";
	MsgItem* flags = new MsgItem{
		"flags",
		flagsstr,
		(ntohs(tcph->headerlength_flags) & 0x003f),
		offset,
		6
	};
	flags->children.push_back(
		new MsgItem{
			"URG",
			flags_urg ? "Set" : "Not Set",
			flags_urg,
			0,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"ACK",
			flags_ack ? "Set" : "Not Set",
			flags_ack,
			1,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"PSH",
			flags_psh ? "Set" : "Not Set",
			flags_psh,
			2,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"RST",
			flags_rst ? "Set" : "Not Set",
			flags_rst,
			3,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"SYN",
			flags_syn ? "Set" : "Not Set",
			flags_syn,
			4,
			1
		}
	);
	flags->children.push_back(
		new MsgItem{
			"FIN",
			flags_fin ? "Set" : "Not Set",
			flags_fin,
			5,
			1
		}
	);
	offset += 6;
	MsgItem* window = new MsgItem{
		"window",
		QString::number(ntohs(tcph->window)),
		ntohs(tcph->window),
		offset,
		16
	};
	offset += 16;
	MsgItem* checksum = new MsgItem{
		"checksum",
		QString::asprintf("0x%04x", ntohs(tcph->checksum)),
		ntohs(tcph->checksum),
		offset,
		16
	};
	offset += 16;
	MsgItem* urgent_pointer = new MsgItem{
		"urgent_pointer",
		QString::number(ntohs(tcph->urgent_pointer)),
		ntohs(tcph->urgent_pointer),
		offset,
		16
	};
	offset += 16;
	// options
	MsgItem* options = NULL;
	if (header_length->value > TCP_BASE_HEADER_LENGTH)
	{
		options = new MsgItem{
			"options",
			QString::number(header_length->value - TCP_BASE_HEADER_LENGTH) + "bytes",
			-1,
			offset,
			(u_int)(header_length->value - TCP_BASE_HEADER_LENGTH) * 8
		};
	}

	int hl = header_length->value;
	MsgItem* tcp_msg = new MsgItem;
	tcp_msg->name = "tcp";
	tcp_msg->offset = protos.back()->offset + protos.back()->length;
	tcp_msg->length = hl * 8;
	tcp_msg->children.push_back(source_port);
	tcp_msg->children.push_back(destination_port);
	tcp_msg->children.push_back(sequence_number);
	tcp_msg->children.push_back(acknowledge_number);
	tcp_msg->children.push_back(header_length);
	tcp_msg->children.push_back(reserved);
	tcp_msg->children.push_back(flags);
	tcp_msg->children.push_back(window);
	tcp_msg->children.push_back(checksum);
	tcp_msg->children.push_back(urgent_pointer);
	if (options) tcp_msg->children.push_back(options);
	
	protos.push_back(tcp_msg);

	frame.src_port = source_port->value;
	frame.des_port = destination_port->value;
	frame.protocol = "tcp";

	// stream index
	StreamMsg* s = new StreamMsg{
		frame.src_addr,
		frame.des_addr,
		frame.src_port,
		frame.des_port,
		frame.protocol
	};
	int idx;
	if ((flags_syn && !flags_ack) || !streams->hasStream(s))
	{
		idx = streams->addStream(s);
	}
	else {
		idx = streams->getStreamIndex(s);
	}
	frame.stream_index = idx;

	// tcp info
	frame.info = "[" + flags->desc + "]" + "  win=" + window->desc;

	payload += hl;
	// upper protocol except tls
	switch (destination_port->value)
	{
	case 80:
	case 21:
	case 23:
	case 25:
	case 110:
		return;
	}

	//tls record protocol
	int data_length = frame.length - (tcp_msg->offset + tcp_msg->length) / 8;
	bool first = true;
	MsgItem* tls_msg = NULL;
	while (true) {
		u_char content_type = *(u_char*)payload;
		int record_length = ntohs(*(u_short*)(payload + 3)) + 5;
		bool isTls = data_length > 0 && record_length <= data_length
			&& (source_port->value == 443 || destination_port->value == 443
				|| (content_type >= 20 && content_type <= 23));

		if (isTls) {
			if (first)
			{
				tls_msg = new MsgItem;
				tls_msg->name = "tls";
				tls_msg->offset = tcp_msg->offset + tcp_msg->length;
				tls_msg->length = 0;
				protos.push_back(tls_msg);
				first = false;
			}
			decodeTLS_Record(payload);
			payload += record_length;
			data_length -= record_length;
		}
		else {
			break;
		}
	}
}

void Packet::decodeTLS_Record(const u_char* payload)
{
	decodeUpper = NULL;
	u_short offset = 0;
	u_char content_type_value = *(u_char*)payload;
	QString content_type_desc;
	switch (content_type_value)
	{
	case 20:
		content_type_desc = "ChangeCipherSpec";
		break;
	case 21:
		content_type_desc = "Alert";
		break;
	case 22:
		content_type_desc = "Handshake";
		break;
	case 23:
		content_type_desc = "ApplicationData";
		break;
	case 24:
		content_type_desc = "HeartBeat";
		break;
	}
	MsgItem* content_type = new MsgItem{
		"content type",
		content_type_desc,
		content_type_value,
		offset,
		8
	};
	offset += 8;
	payload += 1;
	u_short version_value = ntohs(*(u_short*)payload);
	QString version_desc;
	switch (version_value)
	{
	case 0x0301:
		version_desc = "TLS 1.0";
		break;
	case 0x0302:
		version_desc = "TLS 1.1";
		break;
	case 0x0303:
		version_desc = "TLS 1.2";
		break;
	case 0x0304:
		version_desc = "SSL 3.0";
		break;
	}
	MsgItem* version = new MsgItem{
		"version",
		version_desc,
		version_value,
		offset,
		16
	};
	offset += 16;
	payload += 2;
	u_short length_value = ntohs(*(u_short*)payload);
	MsgItem* length = new MsgItem{
		"length",
		QString::number(length_value) + "bytes",
		length_value,
		offset,
		16
	};
	offset += 16;
	payload += 2;

	MsgItem* tls_record_msg = new MsgItem;
	tls_record_msg->name = "tls record layer";
	MsgItem* tls_msg = protos.back();
	tls_record_msg->length = (5 + length->value) * 8;
	tls_record_msg->offset = tls_msg->children.size() == 0 ?
		(tls_msg->offset + tls_msg->length) :
		(tls_msg->children.back()->offset + tls_msg->children.back()->length);
	tls_msg->length += tls_record_msg->length;
	tls_record_msg->children.push_back(content_type);
	tls_record_msg->children.push_back(version);
	tls_record_msg->children.push_back(length);

	protos.back()->children.push_back(tls_record_msg);

	frame.protocol = "tls";
	frame.info = content_type->desc;
}