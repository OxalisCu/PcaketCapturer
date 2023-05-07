#include "DevPool.h"

DevPool::DevPool()
{
	cur = 0;
}

DevPool::DevPool(pcap_if_t* devlist)
{
	cur = 0;
	pcap_if_t* a;
	int i = 0;
	for (a = devlist; a; a = a->next, i++)
	{
		u_long netmask;
		if (a->addresses != NULL)
		{
			netmask = ((struct sockaddr_in*)(a->addresses->netmask))->sin_addr.S_un.S_addr;
		}
		else {
			netmask = 0xffffff;
		}
		data.append(
			new DevMsg{
				QString(a->name),
				QString(a->description),
				netmask
			}
		);
	}
}

DevPool::~DevPool()
{
	clearPool();
}

bool DevPool::isEmpty() const
{
	return getDevSize() == 0;
}

bool DevPool::outOfSize(int index) const
{
	return index >= data.size() + files.size();
}

bool DevPool::isFile(int index) const
{
	return index >= data.size();
}

int DevPool::getDevSize() const
{
	return data.size() + files.size();
}

DevMsg* DevPool::getData(int index) const
{
	return data[index];
}

DevMsg* DevPool::getFile(int index) const
{
	return files[index - data.size()];
}

DevMsg* DevPool::getDev(int index) const
{
	if (outOfSize(index)) return nullptr;
	return isFile(index) ? getFile(index) : getData(index);
}

QVector<QString> DevPool::getDevs() const
{
	QVector<QString> tmp;
	for (auto dev : data) tmp.append(dev->desc);
	for (auto file : files) tmp.append(file->desc);
	return tmp;
}

bool DevPool::curIsFile() const
{
	return isFile(cur);
}

DevMsg* DevPool::getCurDev() const
{
	return getDev(cur);
}

void DevPool::setCurDev(int index)
{
	if (outOfSize(index)) return;
	cur = index;
}

void DevPool::addDev(DevMsg* dev)
{
	files.append(dev);
}

void DevPool::clearPool()
{
	for (auto dev : data)
	{
		delete dev;
	}
	for (auto file : files)
	{
		delete file;
	}
	data.clear();
	files.clear();
}