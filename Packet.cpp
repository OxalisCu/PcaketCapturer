#include "Packet.h"
#include "Utils.h"

Packet::Packet(){}

Packet::Packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& num)
{
	frame_msg = {
		num,
		transTime(header->ts),
		NULL,
		NULL,
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
	for (auto protocol_msg : protocols)
	{
		for (auto msg_item : protocol_msg->items)
		{
			delete msg_item;
		}
		protocol_msg->items.clear();
	}
	protocols.clear();
}

void Packet::decodeEthernet(const u_char* payload)
{
	// obtain the ethernet msg
	Ethernet_Header* ethh = (Ethernet_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	Msg_Item* destination = new Msg_Item{
		"destination",
		MACAddr2String(ethh->destination),
		-1,
		offset,
		48
	};
	offset += 48;
	Msg_Item* source = new Msg_Item{
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
		break;
	default:
		eth_type = "unkown ( 0x" + QString::asprintf("%04x", ntohs(ethh->type)) + " )";
		break;
	}
	Msg_Item* type = new Msg_Item{
		"type",
		eth_type,
		ntohs(ethh->type),
		offset,
		48
	};

	// add protocol item
	Protocol_Msg* eth_msg = new Protocol_Msg;
	eth_msg->name = "ethernet";
	eth_msg->offset = 0;
	eth_msg->length = ETHERNET_HEADER_LENGTH;
	// whether contains FCS or not
	//eth_msg->total_length = frame_msg.length - eth_msg->offset - 4;
	eth_msg->total_length = frame_msg.length - eth_msg->offset;
	eth_msg->items.push_back(destination);
	eth_msg->items.push_back(source);
	eth_msg->items.push_back(type);
	protocols.push_back(eth_msg);
	
	// refresh frame msg
	frame_msg.src = source->desc;
	frame_msg.des = destination->desc;
	frame_msg.protocol = "ethernet";
	frame_msg.stream_index = -1;
	
	// decode the upper protocol
	payload += eth_msg->length;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeIPv4(const u_char* payload)
{
	// obtain the ipv4 msg
	IPv4_Header* ipv4h = (IPv4_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	Msg_Item* version = new Msg_Item{
		"version",
		QString::number((u_char)(ipv4h->version_headerlength & 0xf0) >> 4),
		(u_char)(ipv4h->version_headerlength & 0xf0) >> 4,
		offset,
		4
	};
	offset += 4;
	u_int headerlength = (ipv4h->version_headerlength & 0x0f) * 4;
	Msg_Item* header_length = new Msg_Item{
		"header length",
		QString::number(headerlength),
		(int)headerlength,
		offset,
		4
	};
	offset += 4;
	Msg_Item* differentiated_services = new Msg_Item{
		"differentiated services",
		QString::number(ipv4h->differentiated_services),
		ipv4h->differentiated_services,
		offset,
		8
	};
	offset += 8;
	Msg_Item* total_length = new Msg_Item{
		"total length",
		QString::number(ntohs(ipv4h->total_length)),
		ntohs(ipv4h->total_length),
		offset,
		16
	};
	offset += 16;
	Msg_Item* identification = new Msg_Item{
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
	Msg_Item* flags = new Msg_Item{
		"flags",
		ipv4_flags,
		-1,
		offset,
		3
	};
	flags->children.push_back(
		new Msg_Item{
			"Reserved bit",
			ipv4_reserved ? "Set" : "Not Set",
			ipv4_reserved,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"Don't fragment",
			ipv4_df ? "Set" : "Not Set",
			ipv4_df,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"More fragments",
			ipv4_mf ? "Set" : "Not Set",
			ipv4_mf,
			offset,
			1
		}
	);
	offset += 1;
	Msg_Item* fragment_offset = new Msg_Item{
		"fragment offset",
		QString::number((ntohs(ipv4h->flags_fragmentoffset) & 0xe000) >> 13),
		(ntohs(ipv4h->flags_fragmentoffset) & 0xe000) >> 13,
		offset,
		13
	};
	offset += 13;
	Msg_Item* time_to_live = new Msg_Item{
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
		break;
	case 2:
		ipv4_protocol = "IGMP";
		break;
	case 4:
		ipv4_protocol = "IPv4";
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
	Msg_Item* protocol = new Msg_Item{
		"protocol",
		ipv4_protocol,
		ipv4h->protocol,
		offset,
		8
	};
	offset += 8;
	Msg_Item* header_checksum = new Msg_Item{
		"header checksum",
		QString::asprintf("0x%04x", ntohs(ipv4h->header_checksum)),
		-1,
		offset,
		16
	};
	offset += 16;
	Msg_Item* source = new Msg_Item{
		"source",
		IPv4Addr2String(ipv4h->source),
		-1,
		offset,
		32
	};
	offset += 32;
	Msg_Item* destination = new Msg_Item{
		"destination",
		IPv4Addr2String(ipv4h->destination),
		-1,
		offset,
		32
	};
	offset += 32;
	Msg_Item* options = NULL;
	if (headerlength > IPV4_BASE_HEADER_LENGTH)
	{
		options = new Msg_Item{
			"options",
			QString::number(headerlength - IPV4_BASE_HEADER_LENGTH) + "bytes",
			-1,
			offset,
			headerlength - IPV4_BASE_HEADER_LENGTH
		};
	}

	Protocol_Msg* ipv4_msg = new Protocol_Msg;
	ipv4_msg->name = "ipv4";
	ipv4_msg->offset = protocols.back()->offset + protocols.back()->length;
	ipv4_msg->length = headerlength;
	ipv4_msg->total_length = total_length->value;
	ipv4_msg->items.push_back(version);
	ipv4_msg->items.push_back(header_length);
	ipv4_msg->items.push_back(differentiated_services);
	ipv4_msg->items.push_back(total_length);
	ipv4_msg->items.push_back(identification);
	ipv4_msg->items.push_back(flags);
	ipv4_msg->items.push_back(fragment_offset);
	ipv4_msg->items.push_back(time_to_live);
	ipv4_msg->items.push_back(protocol);
	ipv4_msg->items.push_back(header_checksum);
	ipv4_msg->items.push_back(source);
	ipv4_msg->items.push_back(destination);
	if (options) ipv4_msg->items.push_back(options);

	protocols.push_back(ipv4_msg);

	frame_msg.src = source->desc;
	frame_msg.des = destination->desc;
	frame_msg.protocol = "ipv4";
	
	// decode upper protocol
	payload += ipv4_msg->length;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeIPv6(const u_char* payload)
{
	IPv6_Header* ipv6h = (IPv6_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	Msg_Item* version = new Msg_Item{
		"version",
		QString::number((ntohi(ipv6h->version_traffic_flow) & 0xf0000000) >> 28),
		(int)((ntohi(ipv6h->version_traffic_flow & 0xf0000000)) >> 28),
		offset,
		4
	};
	offset += 4;
	Msg_Item* traffic_class = new Msg_Item{
		"traffic class",
		QString::asprintf("0x%02x", ntohi(ipv6h->version_traffic_flow & 0x0ff00000) >> 20),
		(int)(ntohi(ipv6h->version_traffic_flow & 0x0ff00000) >> 20),
		offset,
		8
	};
	offset += 8;
	Msg_Item* flow_label = new Msg_Item{
		"flow label",
		QString::asprintf("0x%05x", ntohi(ipv6h->version_traffic_flow) & 0x000fffff),
		(int)(ntohi(ipv6h->version_traffic_flow) & 0x000fffff),
		offset,
		20
	};
	offset += 20;
	Msg_Item* payload_length = new Msg_Item{
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
	Msg_Item* next_header = new Msg_Item{
		"next header",
		nextheader,
		ipv6h->next_header,
		offset,
		8
	};
	offset += 8;
	Msg_Item* hop_limit = new Msg_Item{
		"hop limit",
		QString::number(ipv6h->hop_limit),
		ipv6h->hop_limit,
		offset,
		8
	};
	offset += 8;
	Msg_Item* source = new Msg_Item{
		"source",
		IPv6Addr2String(ipv6h->source),
		-1,
		offset,
		128
	};
	offset += 128;
	Msg_Item* destination = new Msg_Item{
		"destination",
		IPv6Addr2String(ipv6h->destination),
		-1,
		offset,
		128
	};
	offset += 128;
	// deal with extension header
	Msg_Item* ext_headers = NULL;
	int ext_len = 0;
	//if (other)
	//{
	//	u_char* p = (u_char*)payload + IPV6_BASE_HEADER_LENGTH;
	//	u_char ext_next_header = *(u_char*)(p + 1);
	//	u_char hdr_ext_len = *(u_char*)p;
	//	ext_headers = new Msg_Item;
	//	ext_headers->name = "extension headers";
	//	ext_headers->length = 0;
	//	ext_headers->offset = offset;
	//	ext_headers->value = -1;
	//	bool ext = true;
	//	while (ext)
	//	{
	//		u_int ext_length = (hdr_ext_len + 1) * 8;
	//		Msg_Item* child = new Msg_Item{
	//			"",
	//			QString::number(ext_length) + "bytes",
	//			(int)ext_length,
	//			offset,
	//			ext_length
	//		};
	//		switch (ext_next_header)
	//		{
	//		case 0:
	//			child->name = "hop by hop options header";
	//			break;
	//		case 43:
	//			child->name = "routing header";
	//			break;
	//		case 44:
	//			child->name = "fragmentation header";
	//			break;
	//		case 50:
	//			child->name = "encapsulating security payload header";
	//			break;
	//		case 51:
	//			child->name = "authentication header";
	//			break;
	//		case 59:
	//			child->name = "destination options for traffic selector";
	//			break;
	//		case 60:
	//			child->name = "destination options header";
	//			break;
	//		case 135:
	//			child->name = "mobility header";
	//			break;
	//		default:
	//			ext = false;
	//			break;
	//		}
	//		if (ext)
	//		{
	//			ext_headers->length += ext_length;
	//			ext_headers->children.push_back(child);
	//			offset += ext_length;
	//			p += ext_length;
	//			ext_len += ext_length;
	//		}
	//	}
	//}

	Protocol_Msg* ipv6_msg = new Protocol_Msg;
	ipv6_msg->name = "ipv6";
	ipv6_msg->offset = protocols.back()->offset + protocols.back()->length;
	ipv6_msg->length = IPV6_BASE_HEADER_LENGTH + ext_len;
	ipv6_msg->total_length = protocols.back()->total_length - protocols.back()->length;
	ipv6_msg->items.push_back(version);
	ipv6_msg->items.push_back(traffic_class);
	ipv6_msg->items.push_back(flow_label);
	ipv6_msg->items.push_back(payload_length);
	ipv6_msg->items.push_back(next_header);
	ipv6_msg->items.push_back(hop_limit);
	ipv6_msg->items.push_back(source);
	ipv6_msg->items.push_back(destination);
	if (ext_headers) ipv6_msg->items.push_back(ext_headers);

	protocols.push_back(ipv6_msg);

	frame_msg.src = source->desc;
	frame_msg.des = destination->desc;
	frame_msg.protocol = "ipv6";

	payload += ipv6_msg->length;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeARP(const u_char* payload)
{

}

void Packet::decodeUDP(const u_char* payload)
{
	UDP_Header* udph = (UDP_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	Msg_Item* source_port = new Msg_Item{
		"source port",
		QString::number(ntohs(udph->source_port)),
		ntohs(udph->source_port),
		offset,
		16
	};
	offset += 16;
	Msg_Item* destination_port = new Msg_Item{
		"destination port",
		QString::number(ntohs(udph->destination_port)),
		ntohs(udph->destination_port),
		offset,
		16
	};
	offset += 16;
	Msg_Item* length = new Msg_Item{
		"length",
		QString::number(ntohs(udph->length)),
		ntohs(udph->length),
		offset,
		16
	};
	offset += 16;
	Msg_Item* checksum = new Msg_Item{
		"checksum",
		QString::asprintf("%04x", ntohs(udph->checksum)),
		ntohs(udph->checksum),
		offset,
		16
	};
	offset += 16;

	Protocol_Msg* udp_msg = new Protocol_Msg;
	udp_msg->name = "udp";
	udp_msg->offset = protocols.back()->offset + protocols.back()->length;
	udp_msg->length = UDP_HEADER_LENGTH;
	udp_msg->total_length = protocols.back()->total_length - protocols.back()->length;
	udp_msg->items.push_back(source_port);
	udp_msg->items.push_back(destination_port);
	udp_msg->items.push_back(length);
	udp_msg->items.push_back(checksum);
	protocols.push_back(udp_msg);

	frame_msg.src = frame_msg.src + ">" + source_port->desc;
	frame_msg.des = frame_msg.des + ">" + destination_port->desc;
	frame_msg.protocol = "udp";

	payload += udp_msg->length;
	if (decodeUpper) (this->*decodeUpper)(payload);
}

void Packet::decodeTCP(const u_char* payload)
{
	TCP_Header* tcph = (TCP_Header*)payload;
	decodeUpper = NULL;
	u_short offset = 0;
	Msg_Item* source_port = new Msg_Item{
		"source port",
		QString::number(ntohs(tcph->source_port)),
		ntohs(tcph->source_port),
		offset,
		16
	};
	offset += 16;
	Msg_Item* destination_port = new Msg_Item{
		"destination port",
		QString::number(ntohs(tcph->destination_port)),
		ntohs(tcph->destination_port),
		offset,
		16
	};
	offset += 16;
	Msg_Item* sequence_number = new Msg_Item{
		"sequence number",
		QString::number(ntohi(tcph->sequence_number)),
		(int)ntohi(tcph->sequence_number),
		offset,
		32
	};
	offset += 32;
	Msg_Item* acknowledge_number = new Msg_Item{
		"acknowledge number",
		QString::number(ntohi(tcph->acknowledge_number)),
		(int)ntohi(tcph->acknowledge_number),
		offset,
		32
	};
	offset += 32;
	Msg_Item* header_length = new Msg_Item{
		"header length",
		QString::number((ntohs(tcph->headerlength_flags) >> 12) * 4),
		(ntohs(tcph->headerlength_flags) >> 12) * 4,
		offset,
		4
	};
	offset += 4;
	Msg_Item* reserved = new Msg_Item{
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
	Msg_Item* flags = new Msg_Item{
		"flags",
		flagsstr,
		(ntohs(tcph->headerlength_flags) & 0x003f),
		offset,
		6
	};
	flags->children.push_back(
		new Msg_Item{
			"URG",
			flags_urg ? "Set" : "Not Set",
			flags_urg,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"ACK",
			flags_ack ? "Set" : "Not Set",
			flags_ack,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"PSH",
			flags_psh ? "Set" : "Not Set",
			flags_psh,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"RST",
			flags_rst ? "Set" : "Not Set",
			flags_rst,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"SYN",
			flags_syn ? "Set" : "Not Set",
			flags_syn,
			offset,
			1
		}
	);
	offset += 1;
	flags->children.push_back(
		new Msg_Item{
			"FIN",
			flags_fin ? "Set" : "Not Set",
			flags_fin,
			offset,
			1
		}
	);
	offset += 1;
	Msg_Item* window = new Msg_Item{
		"window",
		QString::number(ntohs(tcph->window)),
		ntohs(tcph->window),
		offset,
		16
	};
	offset += 16;
	Msg_Item* checksum = new Msg_Item{
		"checksum",
		QString::asprintf("0x%04x", ntohs(tcph->checksum)),
		ntohs(tcph->checksum),
		offset,
		16
	};
	offset += 16;
	Msg_Item* urgent_pointer = new Msg_Item{
		"urgent_pointer",
		QString::number(ntohs(tcph->urgent_pointer)),
		ntohs(tcph->urgent_pointer),
		offset,
		16
	};
	offset += 16;

	Protocol_Msg* tcp_msg = new Protocol_Msg;
	tcp_msg->name = "tcp";
	tcp_msg->offset = protocols.back()->offset + protocols.back()->length;
	tcp_msg->length = TCP_BASE_HEADER_LENGTH;
	tcp_msg->total_length = protocols.back()->total_length - protocols.back()->length;
	tcp_msg->items.push_back(source_port);
	tcp_msg->items.push_back(destination_port);
	tcp_msg->items.push_back(sequence_number);
	tcp_msg->items.push_back(acknowledge_number);
	tcp_msg->items.push_back(header_length);
	tcp_msg->items.push_back(reserved);
	tcp_msg->items.push_back(flags);
	tcp_msg->items.push_back(window);
	tcp_msg->items.push_back(checksum);
	
	protocols.push_back(tcp_msg);

	frame_msg.src = frame_msg.src + ">" + source_port->desc;
	frame_msg.des = frame_msg.des + ">" + destination_port->desc;
	frame_msg.protocol = "tcp";

	// new stream
	if (flags_syn && !flags_ack) frame_msg.stream_index = 1;

	// tcp info
	frame_msg.info = "[ " + flags->desc + "]" 
					+ "  win=" + window->desc;

	payload += tcp_msg->length;
	if (decodeUpper) (this->*decodeUpper)(payload);
}