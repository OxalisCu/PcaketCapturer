#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication.h"
#include "Catcher.h"
#include "Dumper.h"
#include "Filter.h"
#include <QThread>
#include <QFileDialog>

enum ButtonStatus
{
    WAITING,
    CAPTURING
};

enum LineStatus
{
    EDIT,
    NOEDIT
};

class QtWidgetsApplication : public QMainWindow
{
    Q_OBJECT

public:
    explicit QtWidgetsApplication(QWidget* parent = nullptr);
    ~QtWidgetsApplication();

private:
    Catcher *catcher;
    Dumper* dumper; 
    Filter* filter;
    QThread *catcherThread;
    QThread* dumperThread;
    QThread* filterThread;

    Ui::QtWidgetsApplicationClass ui;
    void InitComboBox();
    void InitTableStyle();
    void InitTreeStyle();
    void InitTable2Style();
    void InitContents();
    void updateButtonStatus(ButtonStatus);
    void showPacketMsg(Packet*);
    QTreeWidgetItem* setProtoTree(ProtoMsg*, int);
    void showPacketBytes(Packet*);

signals:
    void startCatcherThread();
    void stopCatcherThread();
    void addCatcherDev(QString path);
    void changeCatcherDev(int index);
    void setDumperPath(QString path, QString tmpfile);
    void startDumperThread();
    void setFilterDev(QString path);
    void setFilterStr(QString str);
    void startFilterThread();

public slots:
    void handleSelectDev(int index);
    void handleStartCatcher();
    void handleStopCatcher();
    void handleImportFile();
    void handlePacketCaptured(Packet* p);
    void handleSelectPacket();
    void handleSelectPacketItem();
    void handleCatcherStopped();
    void handleExportFile();
    void handleSubmitFilter();
    void handleFilterStopped();
};
