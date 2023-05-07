#include "Dumper.h"

Dumper::Dumper(QObject* parent)
{}

Dumper::~Dumper()
{}

void Dumper::setPath(QString des, QString src)
{
	this->des = des;
	this->src = src;
}

void Dumper::startDump()
{
	QFile srcFile(src);
	if (srcFile.exists())
	{
		srcFile.copy(des);
	}
}