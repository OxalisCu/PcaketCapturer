#pragma once
#include "Packet.h"

class PktPool
{
private:
	QVector<Packet*> data;

	bool outOfSize(int) const;
public:
	PktPool();
	~PktPool();

	bool isEmpty() const;
	int getPktSize() const;
	Packet* getPkt(int) const;
	void addPkt(Packet*);
	void clearPool();
};