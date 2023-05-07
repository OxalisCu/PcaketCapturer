#pragma once
#include <QOBject>
#include "Global.h"
#include "DevPool.h"
#include "Packet.h"

class Filter : public QObject
{
	Q_OBJECT
private:
	pcap_t* adhandle;
	struct bpf_program fcode;

	DevMsg dev;
	QString filter;

	bool filtering;

	bool openAdapter();
	void closeAdapter();
public:
	explicit Filter(QObject* parent = nullptr);
	~Filter();

	bool validateFilter(QString);
signals:
	void newPacketFiltered(Packet*);
	void filterStopped();

public slots:
	void setDev(QString);
	void setFilter(QString);
	void startFilter();
};