#include "StreamPool.h"
#include <QThread>

StreamPool::StreamPool()
{
	num.resize(STREAM_NUM);
}

StreamPool::~StreamPool()
{
	for (auto s : data)
	{
		delete s;
	}
	data.clear();
}

QString StreamPool::generKey(StreamMsg* s)
{
	QString key;
	if (s->client_port < s->server_port)
	{
		key = s->proto + "_" + s->client_addr + "_" + QString::number(s->client_port)
			+ "_" + s->server_addr + "_" + QString::number(s->server_port);
	}
	else {
		key = s->proto + "_" + s->server_addr + "_" + QString::number(s->server_port)
			+ "_" + s->client_addr + "_" + QString::number(s->client_port);
	}
	return key;
}

bool StreamPool::hasStream(StreamMsg* s)
{
	QString key = generKey(s);
	return data.contains(key);
}

int StreamPool::getStreamIndex(StreamMsg* s)
{
	QString key = generKey(s);
	if (hasStream(s))
	{
		return data[key]->index.back();
	}
	else {
		return -1;
	}
}

int StreamPool::addStream(StreamMsg* s)
{
	QString key = generKey(s);
	StreamType type = getStreamType(s->proto);
	if (!hasStream(s))
	{
		data[key] = s;
		s->index.push_back(num[type]);
	} else {
		data[key]->index.push_back(num[type]);
	}
	return num[type]++;
}

QString StreamPool::getStreamName(StreamType type)
{
	QString STREAM_TYPE[STREAM_NUM] = {
		"udp", "tcp"
	};
	return STREAM_TYPE[type];
}

StreamType StreamPool::getStreamType(QString name)
{
	StreamType type;
	if (name == "udp")
	{
		type = UDP;
	}
	else if (name == "tcp")
	{
		type = TCP;
	}
	return type;
}