#include "Filter.h"

Filter::Filter(QObject* parent)
{
}

Filter::~Filter()
{}

void Filter::setDev(QString path)
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
	dev = DevMsg{
		QString(source),
		path,
		0xffffff
	};
}

void Filter::setFilter(QString f)
{
	filter = f;
}

bool Filter::validateFilter(QString filter)
{
	struct bpf_program fcode;
	return pcap_compile_nopcap(65536, 0, &fcode, filter.toLatin1(), 1, dev.netmask) >= 0;
}

bool Filter::openAdapter()
{
	// open adaptor
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	if ((adhandle = pcap_open(
		(const char*)(dev.name.toLatin1()),
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

void Filter::closeAdapter()
{
	if (adhandle)
	{
		pcap_close(adhandle);
		adhandle = NULL;
	}
}

void Filter::startFilter()
{
	// open adaptor
	if (!openAdapter())
	{
		emit filterStopped();
		return;
	}
	// compile filter
	if (pcap_compile(adhandle, &fcode, filter.toLatin1(), 1, dev.netmask) < 0 ||
		pcap_setfilter(adhandle, &fcode) < 0)
	{
		emit filterStopped();
		return;
	}
	// start catch
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int num = 0;
	StreamPool streams;
	filtering = true;
	while (filtering && (res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		Packet* pkt = new Packet(header, pkt_data, num++, &streams);
		// process signals and events
		emit newPacketFiltered(pkt);
	}
	// stopped with an error or EOF
	if (filtering && (res == -1 || res == -2)) {
		emit filterStopped();
		return;
	}
}