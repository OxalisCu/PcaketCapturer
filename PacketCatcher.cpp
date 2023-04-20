#include "PacketCatcher.h"
#include <QThread>
#include <QApplication>

PacketCatcher::PacketCatcher(QObject* parent)
{
	m_adhandle = NULL;
	m_dumper = NULL;
	filter = "";
	filtering = false;
	capturing = false;
	devnum = 0;
	curDev = -1;
	tcp_stream = 0;
	udp_stream = 0;
	if (!initDevList())
	{
		m_devlist = NULL;
	}
}

PacketCatcher::~PacketCatcher()
{
	m_adhandle = NULL;
	m_dumper = NULL;
	if (m_devlist)
	{
		pcap_freealldevs(m_devlist);
		m_devlist = NULL;
	}
	if (!m_devstrlist.isEmpty())
	{
		m_devstrlist.clear();
	}
	clearPkts();
}

void PacketCatcher::clearPkts()
{
	if (!m_pkts.isEmpty())
	{
		for (int i = 0; i < m_pkts.size(); i++)
		{
			delete m_pkts[i];
		}
		m_pkts.clear();
	}
}

bool PacketCatcher::initDevList()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &m_devlist, errbuf) == -1)
	{
		return false;
	}
	pcap_if_t* a;
	int i = 0;
	for (a = m_devlist; a; a = a->next, i++)
	{
		u_long netmask;
		if (a->addresses != NULL)
		{
			netmask = ((struct sockaddr_in*)(a->addresses->netmask))->sin_addr.S_un.S_addr;
		}
		else {
			netmask = 0xffffff;
		}
		m_devstrlist.append(
			new DevMsg{
				QString(a->name),
				QString(a->description),
				netmask
			}
		);
	}
	devnum = i;
	return true;
}

pcap_if_t* PacketCatcher::getCurDevMsg() const
{
	int i = 0;
	pcap_if_t* a;
	for (a = m_devlist; a && i < curDev; a = a->next, i++);
	return a;
}

bool PacketCatcher::isLocalDev() const
{
	return curDev >= devnum;
}

bool PacketCatcher::openFilter()
{
	struct bpf_program fcode;
	return pcap_compile(m_adhandle, &fcode, filter.toLatin1(), 1, m_devstrlist[curDev]->netmask) >= 0 &&
		pcap_setfilter(m_adhandle, &fcode) >= 0;
}

bool PacketCatcher::openAdapter()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	if (filtering)
	{
		if (pcap_createsrcstr(
			source,
			PCAP_SRC_FILE,
			NULL,
			NULL,
			(const char*)tmpfile.toLatin1(),
			errbuf
		) != 0) {
			return false;
		}
	}
	if ((m_adhandle = pcap_open(
		filtering ? source : (const char*)(m_devstrlist[curDev]->name.toLatin1()),
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		READ_PACKET_TIMEOUT,
		NULL,
		errbuf
	)) == NULL) {
		pcap_freealldevs(m_devlist);
		m_devlist = NULL;
		return false;
	}
	pcap_freealldevs(m_devlist);
	m_devlist = NULL;
	// open dump
	if (!isLocalDev() && !filtering) {
		QDateTime currentTime;
		QDir dir;
		dir.mkdir("tmp");
		tmpfile = ".\\tmp\\PacketCatcher_" + currentTime.currentDateTime().toString("yyyyMMdd_hhmmss") + ".pcap";
		m_dumper = pcap_dump_open(m_adhandle, (const char*)(tmpfile.toLatin1()));
		if (!m_dumper) return false;
	}
	else {
		tmpfile = m_devstrlist[curDev]->name;
	}

	return true;
}

void PacketCatcher::closeAdapter()
{
	if (m_adhandle)
	{
		pcap_close(m_adhandle);
		m_adhandle = NULL;
	}
	if (m_dumper)
	{
		pcap_dump_close(m_dumper);
		m_dumper = NULL;
	}
}

// dev
bool PacketCatcher::setCurDev(int index)
{
	if (index < 0 || index > m_devstrlist.size()) return false;
	curDev = index;
	return true;
}

bool PacketCatcher::addLocalDev(QString path)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	if (pcap_createsrcstr(
		source,
		PCAP_SRC_FILE,
		NULL,
		NULL,
		(const char*)path.toLatin1(),
		errbuf
	) != 0) {
		return false;
	}
	m_devstrlist.append(
		new DevMsg{
			QString(source),
			QString(path),
			0xffffff
		}
	);
	return true;
}

// capture
void PacketCatcher::startCapture()
{
	if (!openAdapter() || !openFilter()) return;
	clearPkts();

	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	int num = 0;
	capturing = true;
	while (capturing && (res = pcap_next_ex(m_adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;
		Packet* pkt = new Packet(header, pkt_data, num++);
		// stream folow
		if (pkt->frame_msg.protocol == "udp")
		{
			QString stream_key_1 = "udp_" + pkt->frame_msg.src + "-" + pkt->frame_msg.des;
			QString stream_key_2 = "udp_" + pkt->frame_msg.des + "-" + pkt->frame_msg.src;
			if (!streams.contains(stream_key_1) && !streams.contains(stream_key_2))
			{
				pkt->frame_msg.stream_index = udp_stream;
				streams[stream_key_1].push_back(udp_stream++);
			}
			else {
				QString stream_key = streams.contains(stream_key_1) ? stream_key_1 : stream_key_2;
				pkt->frame_msg.stream_index = streams[stream_key].back();
			}
		}
		if (pkt->frame_msg.protocol == "tcp")
		{
			QString stream_key_1 = "tcp_" + pkt->frame_msg.src + "-" + pkt->frame_msg.des;
			QString stream_key_2 = "tcp_" + pkt->frame_msg.des + "-" + pkt->frame_msg.src;
			if (!streams.contains(stream_key_1) && !streams.contains(stream_key_2) || pkt->frame_msg.stream_index == 1)
			{
				pkt->frame_msg.stream_index = tcp_stream;
				streams[stream_key_1].push_back(tcp_stream++);
			}
			else {
				QString stream_key = streams.contains(stream_key_1) ? stream_key_1 : stream_key_2;
				pkt->frame_msg.stream_index = streams[stream_key].back();
			}
		}
		// store to the local file
		if (!isLocalDev() && !filtering)
		{
			pcap_dump((u_char*)m_dumper, header, pkt_data);
		}
		m_pkts.append(pkt);
		emit newPacketCaptured(pkt);
		QApplication::processEvents();
	}
	// stopped with an error
	if (capturing && (res == -1 || res == -2)) {
		emit captureStopped();
		filtering = false;
	}
}

void PacketCatcher::stopCapture()
{
	if (capturing || filtering)
	{
		capturing = false;
		filtering = false;
		closeAdapter();
	}
}

// export
void PacketCatcher::saveFile(QString path)
{
	if (capturing) return;
	QFile tmpFile(tmpfile);
	if (tmpFile.exists())
	{
		tmpFile.copy(path);
	}
}

// filter
bool PacketCatcher::validateFilter(QString str)
{
	struct bpf_program fcode;
	return pcap_compile_nopcap(65536, 0, &fcode, str.toLatin1(), 1, m_devstrlist[curDev]->netmask) >= 0;
}

void PacketCatcher::setFilter(QString str)
{
	filter = str;
}

void PacketCatcher::startFilter()
{
	filtering = true;
	startCapture();
}