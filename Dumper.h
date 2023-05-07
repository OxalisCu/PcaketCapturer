#pragma once
#include <QOBject>
#include "Global.h"

class Dumper : public QObject
{
	Q_OBJECT
private:
	QString des;
	QString src;
public:
	explicit Dumper(QObject* parent = nullptr);
	~Dumper();

public slots:
	void setPath(QString, QString);
	void startDump();
};