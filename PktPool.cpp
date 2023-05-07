#include "PktPool.h"

PktPool::PktPool()
{
}

PktPool::~PktPool()
{
	clearPool();
}

bool PktPool::outOfSize(int index) const
{
	return index >= data.size();
}

bool PktPool::isEmpty() const
{
	return data.isEmpty();
}

int PktPool::getPktSize() const
{
	return data.size();
}

Packet* PktPool::getPkt(int index) const
{
	if (outOfSize(index)) return nullptr;
	return data[index];
}

void PktPool::addPkt(Packet* pkt)
{
	data.append(pkt);
}

void PktPool::clearPool()
{
	for (auto pkt : data)
	{
		delete pkt;
	}
	data.clear();
}