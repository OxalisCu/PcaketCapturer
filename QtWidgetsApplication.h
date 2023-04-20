#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_QtWidgetsApplication.h"
#include "PacketCatcher.h"
#include <QThread>
#include <QFileDialog>
#include <QMessageBox>

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

    void debug(QString str)
    {
        QMessageBox::about(
            this,
            "debug",
            str
        );
    }

private:
    PacketCatcher *catcher;
    QThread catcherThread;

    Ui::QtWidgetsApplicationClass ui;
    bool isContentEmpty();
    bool isDevSelected();
    void InitComboBox();
    void InitLineEdit();
    void InitTableStyle();
    void InitTreeStyle();
    void InitTable2Style();
    void InitContents();
    void updateButtonStatus(ButtonStatus);
    void updateLineStatus(LineStatus);
    void showPacketMsg(Packet* p);
    void showPacketBytes(Packet* p);

signals:
    void startCatcherThread();
    void stopCatcherThread();
    void addCatcherDev(QString path);
    void changeCatcherDev(int index);
    void saveCatcherFile(QString path);
    void setCatcherFilter(QString str);
    void startCatcherFilter();

public slots:
    void handleSelectDev(int index);
    void handleStartCatcher();
    void handleStopCatcher();
    void handleImportFile();
    void handleExportFile();
    void handleSubmitFilter();
    void handlePacketCaptured(Packet* p);
    void handleSelectPacket();
    void handleSelectPacketItem();
    void handleCatcherStopped();
};
