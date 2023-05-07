#pragma once
#include "Global.h"

const int STREAM_NUM = 2;

enum StreamType {
	UDP = 0,
	TCP,
};

typedef struct StreamMsg
{
	QString client_addr;
	QString server_addr;
	int client_port;
	int server_port;
	QString proto;
	QVector<int> index;
}StreamMsg;

class StreamPool
{
private:
	QMap<QString, StreamMsg*> data;
	QVector<int> num;

	StreamType getStreamType(QString);
	QString getStreamName(StreamType);
	QString generKey(StreamMsg*);
public:
	StreamPool();
	~StreamPool();

	bool hasStream(StreamMsg*);
	int getStreamIndex(StreamMsg*);
	int addStream(StreamMsg*);
};