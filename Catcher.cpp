#include "Catcher.h"
#include <QApplication>
#include <QThread>

Catcher::Catcher(QObject* parent)
{
	initDevList();
	pkts = new PktPool();
	streams = new StreamPool();
}

Catcher::~Catcher()
{
	if (devs) delete devs;
	if (pkts) delete pkts;
	if (streams) delete streams;
	if (devlist) pcap_freealldevs(devlist);
}

QString Catcher::getTmpfile()
{
	return tmpfile;
}

void Catcher::initDevList()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &devlist, errbuf) == -1)
	{
		devs = new DevPool();
	}
	else {
		devs = new DevPool(devlist);
	}
}

void Catcher::setCurDev(int index)
{
	devs->setCurDev(index);
}

DevMsg Catcher::getDev(int index)
{
	return *devs->getDev(index);
}

void Catcher::addLocalDev(QString path)
{
	char source[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_createsrcstr(
		source,
		PCAP_SRC_FILE,
		NULL,
		NULL,
		path.toLatin1(),
		errbuf
	) != 0)
	{
		return;
	}
	devs->addDev(
		new DevMsg{
			QString(source),
			path,
			0xffffff
		}
	);
}

bool Catcher::openAdapter()
{
	// open adaptor
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	if ((adhandle = pcap_open(
		(const char*)(devs->getCurDev()->name.toLatin1()),
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		READ_PACKET_TIMEOUT,
		NULL,
		errbuf
	)) == NULL) {
		return false;
	}
	return true;
}

void Catcher::closeAdapter()
{
	if (adhandle)
	{
		pcap_close(adhandle);
		adhandle = NULL;
	}
}

void Catcher::startCatchDev()
{
	// open adaptor
	if (!openAdapter())
	{
		emit captureStopped();
		return;
	}
	// store to tmpfile
	QDateTime currentTime;
	QDir dir;
	dir.mkdir("tmp");
	tmpfile = ".\\tmp\\Catcher_" + currentTime.currentDateTime().toString("yyyyMMdd_hhmmss") + ".pcap";
	dumper = pcap_dump_open(adhandle, (const char*)(tmpfile.toLatin1()));
	if (!dumper)
	{
		emit captureStopped();
		return;
	}
	// start catch
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int num = 0;
	capturing = true;
	while (capturing && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		// decode pkt
		Packet* pkt = new Packet(header, pkt_data, num++, streams);
		// add to pkt pool
		pkts->addPkt(pkt);
		// store to tmpfile
		pcap_dump((u_char*)dumper, header, pkt_data);
		// process signals and events
		emit newPacketCaptured(pkt);
		QApplication::processEvents();
	}
	// stopped with an error or EOF
	if (capturing && (res == -1 || res == -2)) {
		emit captureStopped();
		return;
	}
}

void Catcher::startCatchFile()
{
	// open adaptor
	if (!openAdapter())
	{
		emit captureStopped();
		return;
	}
	// start catch
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int num = 0;
	tmpfile = devs->getCurDev()->desc;
	capturing = true;
	while (capturing && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		Packet* pkt = new Packet(header, pkt_data, num++, streams);
		pkts->addPkt(pkt);
		// process signals and events
		emit newPacketCaptured(pkt);
		QApplication::processEvents();
	}
	// stopped with an error or EOF
	if (capturing && (res == -1 || res == -2)) {
		emit captureStopped();
		return;
	}
}

void Catcher::clearCatchRes()
{
	pkts->clearPool();
	//if (tmpfile != nullptr)
	//{
	//	QFile::remove(tmpfile);
	//	tmpfile = nullptr;
	//}
}

void Catcher::startCatch()
{
	clearCatchRes();
	if (devs->curIsFile())
	{
		startCatchFile();
	}
	else {
		startCatchDev();
	}
}

void Catcher::stopCatch()
{
	capturing = false;
	if (dumper)
	{
		pcap_dump_close(dumper);
		dumper = NULL;
	}
	closeAdapter();
}