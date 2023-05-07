#pragma once
#include <QObject>
#include "Global.h"
#include "Packet.h"
#include "DevPool.h"
#include "PktPool.h"
#include "StreamPool.h"

class Catcher : public QObject
{
	Q_OBJECT
private:
	pcap_t			*adhandle;
	pcap_if_t		*devlist;
	pcap_dumper_t	*dumper;

	QString tmpfile;

	bool capturing;

	void startCatchDev();
	void startCatchFile();
	void initDevList();
	bool openAdapter();
	void closeAdapter();
	void clearCatchRes();
public:
	DevPool* devs;
	PktPool* pkts;
	StreamPool* streams;

	explicit Catcher(QObject* parent = nullptr);
	~Catcher();

	DevMsg getDev(int);
	QString getTmpfile();
signals:
	void newPacketCaptured(Packet*);
	void captureStopped();

public slots:
	void setCurDev(int);
	void addLocalDev(QString);
	void startCatch();
	void stopCatch();
};
