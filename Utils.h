#pragma once
#include "Global.h"

QDateTime transTime(struct timeval ts)
{
	QDateTime time = QDateTime::fromSecsSinceEpoch(ts.tv_sec);
	time = time.addMSecs(ts.tv_usec);
	return time;
}

QString MACAddr2String(const u_char addr[])
{
	QString strAddr;
	int length = 6;
	QString split = ":";
	for (int i = 0; i < length; ++i)
	{
		strAddr += QString::asprintf("%02x", addr[i]);
		if (i != length - 1)
			strAddr += split;
	}
	return strAddr;
}

QString IPv4Addr2String(const u_char addr[])
{
	QString strAddr;
	int length = 4;
	QString split = ".";
	for (int i = 0; i < length; ++i)
	{
		strAddr += QString::asprintf("%d", addr[i]);
		if (i != length - 1)
			strAddr += split;
	}
	return strAddr;
}

QString IPv6Addr2String(const u_short addr[])
{
	QString strAddr;
	int length = 8;
	QString split = ":";
	for (int i = 0; i < length; ++i)
	{
		strAddr += QString::asprintf("%x", ntohs(addr[i]));
		if (i != length - 1)
			strAddr += split;
	}
	return strAddr;
}

#define Swap32(A) ((((u_int)(A) & 0xff000000) >> 24) | \
				   (((u_int)(A) & 0x00ff0000) >>  8) | \
				   (((u_int)(A) & 0x0000ff00) <<  8) | \
				   (((u_int)(A) & 0x000000ff) << 24))

u_int ntohi(u_int num)
{
	return LITTLEENDIAN ? Swap32(num) : num;
}