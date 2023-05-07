#pragma once
#include "Global.h"

typedef struct DevMsg
{
	QString name;
	QString desc;
	u_long netmask;
}DevMsg;

class DevPool
{
private:
	QVector<DevMsg*> data;
	QVector<DevMsg*> files;
	int cur;

	bool isFile(int) const;
	bool outOfSize(int) const;
	DevMsg* getData(int) const;
	DevMsg* getFile(int) const;
public:
	DevPool();
	DevPool(pcap_if_t*);
	~DevPool();

	bool isEmpty() const;
	int getDevSize() const;
	DevMsg* getDev(int) const;
	QVector<QString> getDevs() const;
	bool curIsFile() const;
	DevMsg* getCurDev() const;
	void setCurDev(int);
	void addDev(DevMsg*);
	void clearPool();
};