#pragma once
#include "Global.h"
#include "ProtocolHeader.h"
#include "ProtocolMsg.h"

class Packet
{
public:
	u_char* pkt_data;
	Frame_Msg frame_msg;
	QVector<Protocol_Msg*> protocols;
	void (Packet::* decodeUpper)(const u_char*);

	Packet();
	Packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& num);
	~Packet();

private:
	void decodeEthernet(const u_char* payload);
	void decodeIPv4(const u_char* payload);
	void decodeIPv6(const u_char* payload);
	void decodeARP(const u_char* payload);
	void decodeTCP(const u_char* payload);
	void decodeUDP(const u_char* payload);
};