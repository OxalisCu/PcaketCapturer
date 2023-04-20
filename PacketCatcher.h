#pragma once
#include <QObject>
#include "Global.h"
#include "Packet.h"

const int READ_PACKET_TIMEOUT = 1000;

struct DevMsg
{
	QString name;
	QString desc;
	u_long netmask;
};

class PacketCatcher : public QObject
{
	Q_OBJECT
private:
	pcap_t			*m_adhandle;
	pcap_if_t		*m_devlist;
	pcap_dumper_t	*m_dumper;

	QString tmpfile;
	QString filter;
	int devnum;
	int curDev;
	bool capturing;
	bool filtering;

public:
	QVector<DevMsg*> m_devstrlist;
	QVector<Packet*> m_pkts;
	u_int tcp_stream;
	u_int udp_stream;
	QMap<QString, QVector<int>> streams;

	explicit PacketCatcher(QObject* parent = nullptr);
	~PacketCatcher();

	bool initDevList();
	pcap_if_t* getCurDevMsg() const;
	bool isLocalDev() const;
	bool validateFilter(QString str);
	bool openFilter();
	void clearPkts();

	bool openAdapter();
	void closeAdapter();

	// running on child thread
signals:
	void newPacketCaptured(Packet* p);
	void captureStopped();

public slots:
	bool setCurDev(int index);
	void startCapture();
	void stopCapture();
	bool addLocalDev(QString path);
	void saveFile(QString path);
	void setFilter(QString str);
	void startFilter();
};
