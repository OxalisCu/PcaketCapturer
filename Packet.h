#pragma once
#include "Global.h"
#include "StreamPool.h"
#include "ProtoHeader.h"

typedef struct FrameMsg
{
	u_short num;		// start from 1
	QDateTime time;
	QString src_addr;
	QString des_addr;
	int src_port;
	int des_port;
	QString	protocol;
	u_int length;		// byte
	QString info;
	u_int stream_index;
}FrameMsg;

typedef struct ProtoMsg
{
	QString name;
	QString desc;
	int value;		// default value is -1
	u_int offset;		// bit
	u_int length;		// bit
	QVector<ProtoMsg*> children;
}MsgItem;

class Packet
{
public:
	u_char* pkt_data;
	FrameMsg frame;
	QVector<ProtoMsg*> protos;
	StreamPool* streams;

	Packet();
	Packet(const struct pcap_pkthdr* header, const u_char* pkt_data, const u_short& num, StreamPool* ss);
	~Packet();
	void clearProtos(ProtoMsg*);

private:
	void (Packet::* decodeUpper)(const u_char*);
	void decodeEthernet(const u_char* payload);
	void decodeIPv4(const u_char* payload);
	void decodeIPv6(const u_char* payload);
	void decodeARP(const u_char* payload);
	void decodeTCP(const u_char* payload);
	void decodeUDP(const u_char* payload);
	void decodeICMP(const u_char* payload);
	void decodeTLS_Record(const u_char* payload);
};