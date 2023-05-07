#include "QtWidgetsApplication.h"

QtWidgetsApplication::QtWidgetsApplication(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    connect(ui.comboBox, static_cast<void (QComboBox::*)(int)>(& QComboBox::currentIndexChanged), this, &QtWidgetsApplication::handleSelectDev);
    connect(ui.pushButtonStart, &QPushButton::clicked, this, &QtWidgetsApplication::handleStartCatcher);
    connect(ui.pushButtonEnd, &QPushButton::clicked, this, &QtWidgetsApplication::handleStopCatcher);
    connect(ui.pushButtonImport, &QPushButton::clicked, this, &QtWidgetsApplication::handleImportFile);
    connect(ui.tableWidget, &QTableWidget::itemSelectionChanged, this, &QtWidgetsApplication::handleSelectPacket);
    connect(ui.treeWidget, &QTreeWidget::itemSelectionChanged, this, &QtWidgetsApplication::handleSelectPacketItem);
    connect(ui.pushButtonExport, &QPushButton::clicked, this, &QtWidgetsApplication::handleExportFile);
    connect(ui.lineEdit, &QLineEdit::returnPressed, this, &QtWidgetsApplication::handleSubmitFilter);

    InitTableStyle();
    InitTreeStyle();
    InitTable2Style();

    // threads
    catcher = new Catcher;
    catcherThread = new QThread;
    catcher->moveToThread(catcherThread);
    catcherThread->start();
    connect(this, &QtWidgetsApplication::startCatcherThread, catcher, &Catcher::startCatch);
    connect(this, &QtWidgetsApplication::stopCatcherThread, catcher, &Catcher::stopCatch);
    connect(this, &QtWidgetsApplication::changeCatcherDev, catcher, &Catcher::setCurDev);
    connect(this, &QtWidgetsApplication::addCatcherDev, catcher, &Catcher::addLocalDev);
    connect(catcher, &Catcher::newPacketCaptured, this, &QtWidgetsApplication::handlePacketCaptured);
    connect(catcher, &Catcher::captureStopped, this, &QtWidgetsApplication::handleCatcherStopped);

    dumper = new Dumper;
    dumperThread = new QThread;
    dumper->moveToThread(dumperThread);
    dumperThread->start();
    connect(this, &QtWidgetsApplication::setDumperPath, dumper, &Dumper::setPath);
    connect(this, &QtWidgetsApplication::startDumperThread, dumper, &Dumper::startDump);

    filter = new Filter;
    filterThread = new QThread;
    filter->moveToThread(filterThread);
    filterThread->start();
    connect(this, &QtWidgetsApplication::setFilterDev, filter, &Filter::setDev);
    connect(this, &QtWidgetsApplication::setFilterStr, filter, &Filter::setFilter);
    connect(this, &QtWidgetsApplication::startFilterThread, filter, &Filter::startFilter);
    connect(filter, &Filter::newPacketFiltered, this, &QtWidgetsApplication::handlePacketCaptured);
    connect(filter, &Filter::filterStopped, this, &QtWidgetsApplication::handleFilterStopped);

    InitComboBox();
}

QtWidgetsApplication::~QtWidgetsApplication()
{
    emit stopCatcherThread();
}

void QtWidgetsApplication::InitComboBox()
{
    ui.comboBox->clear();
    for (auto dev : catcher->devs->getDevs())
    {
        ui.comboBox->addItem(dev);
    }
    ui.comboBox->setCurrentIndex(0);
}

void QtWidgetsApplication::InitContents()
{
    ui.tableWidget->setRowCount(0);
    ui.tableWidget->clearContents();
    ui.treeWidget->clear();
    ui.tableWidget_2->clear();
}

void QtWidgetsApplication::InitTableStyle()
{
    ui.tableWidget->setColumnWidth(0, 60);
    ui.tableWidget->setColumnWidth(1, 120);
    ui.tableWidget->setColumnWidth(2, 250);
    ui.tableWidget->setColumnWidth(3, 250);
    ui.tableWidget->setColumnWidth(4, 100);
    ui.tableWidget->setColumnWidth(5, 80);
}

void QtWidgetsApplication::InitTreeStyle()
{
    ui.treeWidget->setHeaderHidden(true);
}

void QtWidgetsApplication::InitTable2Style()
{
    ui.tableWidget_2 ->verticalHeader()->setVisible(true);
    ui.tableWidget_2->horizontalHeader()->setVisible(false);
    ui.tableWidget_2->setColumnCount(16);
    QPalette palette;
    palette.setColor(QPalette::Highlight, QColor::fromRgb(4, 124, 212));
    palette.setColor(QPalette::HighlightedText, QColor::fromRgb(255, 255, 255));
    ui.tableWidget_2->setPalette(palette);
}

void QtWidgetsApplication::updateButtonStatus(ButtonStatus s)
{
    switch (s)
    {
    case WAITING:
        ui.lineEdit->setEnabled(true);
        ui.pushButtonStart->setEnabled(
            !catcher->devs->isEmpty()
        );
        ui.pushButtonEnd->setEnabled(false);
        ui.pushButtonImport->setEnabled(true);
        ui.pushButtonExport->setEnabled(
            !catcher->pkts->isEmpty()
        );
        ui.comboBox->setEnabled(true);
        break;
    case CAPTURING:
        ui.lineEdit->setEnabled(false);
        ui.pushButtonStart->setEnabled(false);
        ui.pushButtonEnd->setEnabled(true);
        ui.pushButtonImport->setEnabled(false);
        ui.pushButtonExport->setEnabled(false);
        ui.comboBox->setEnabled(false);
        break;
    }
}

void QtWidgetsApplication::showPacketMsg(Packet* p)
{
    ui.treeWidget->clear();
    // frame msg
    QTreeWidgetItem* frame = new QTreeWidgetItem({ "frame" });
    frame->addChild(new QTreeWidgetItem({ "frame number:  " + QString::number(p->frame.num) }));
    frame->addChild(new QTreeWidgetItem({ "frame length:  " + QString::number(p->frame.length) + "bytes"}));
    frame->addChild(new QTreeWidgetItem({ "capture time:  " + p->frame.time.toString("yyyy-MM-dd mm:ss:zzz")}));
    frame->addChild(new QTreeWidgetItem({ "upper protocol:  " + p->frame.protocol}));
    if (p->frame.stream_index != -1) frame->addChild(new QTreeWidgetItem({ p->frame.protocol + " stream index:  " + QString::number(p->frame.stream_index)}));
    ui.treeWidget->addTopLevelItem(frame);
    // protocols
    int offset = 0;
    for (ProtoMsg* proto : p->protos)
    {
        ui.treeWidget->addTopLevelItem(setProtoTree(proto, offset));
    }
}

QTreeWidgetItem* QtWidgetsApplication::setProtoTree(ProtoMsg* proto, int offset)
{
    QTreeWidgetItem* protoWidget = new QTreeWidgetItem({ proto->name + ":  " + proto->desc});
    offset += proto->offset;
    protoWidget->setData(1, 0, offset);
    protoWidget->setData(2, 0, proto->length);
    if (!proto->children.isEmpty())
    {
        for (ProtoMsg* p : proto->children)
        {
            protoWidget->addChild(setProtoTree(p, offset));
        }
    }
    return protoWidget;
}

void QtWidgetsApplication::showPacketBytes(Packet* p)
{
    ui.tableWidget_2->clear();
    int length = p->frame.length;
    int col = 16;
    int row = length / col + (length % col == 0 ? 0 : 1);
    ui.tableWidget_2->setRowCount(row);
    for (int i = 0; i < row; i++)
    {
        ui.tableWidget_2->setVerticalHeaderItem(i, new QTableWidgetItem(QString::asprintf("%04x", i)));
    }
    for (int i = 0; i < length; i++)
    {
        ui.tableWidget_2->setItem(i / col, i % col, new QTableWidgetItem(QString::asprintf("%02x", p->pkt_data[i])));
    }
}

void QtWidgetsApplication::handleSelectDev(int index)
{
    emit changeCatcherDev(index);
    updateButtonStatus(WAITING);
}

void QtWidgetsApplication::handleStartCatcher()
{
    // create the catcher thread
    updateButtonStatus(CAPTURING);
    InitContents();
    emit startCatcherThread();
}

void QtWidgetsApplication::handleStopCatcher()
{
    emit stopCatcherThread();
    updateButtonStatus(WAITING);
}

void QtWidgetsApplication::handleImportFile()
{
    QString path = QFileDialog::getOpenFileName(this, "select .pcap file", "./", "Text files (*.pcap)");
    emit addCatcherDev(path);
    InitComboBox();
}

void QtWidgetsApplication::handlePacketCaptured(Packet *p)
{
    int rownum = ui.tableWidget->rowCount();
    ui.tableWidget->setRowCount(rownum + 1);
    ui.tableWidget->setItem(rownum, 0, new QTableWidgetItem(QString::number(p->frame.num)));
    ui.tableWidget->setItem(rownum, 1, new QTableWidgetItem(p->frame.time.toString("mm:ss:zzz")));
    ui.tableWidget->setItem(rownum, 2, new QTableWidgetItem(p->frame.src_addr + (p->frame.src_port == 0 ? "" : (" [" + QString::number(p->frame.src_port) + "]"))));
    ui.tableWidget->setItem(rownum, 3, new QTableWidgetItem(p->frame.des_addr + (p->frame.src_port == 0 ? "" : (" [" + QString::number(p->frame.des_port) + "]"))));
    ui.tableWidget->setItem(rownum, 4, new QTableWidgetItem(p->frame.protocol));
    ui.tableWidget->setItem(rownum, 5, new QTableWidgetItem(QString::number(p->frame.length)));
    ui.tableWidget->setItem(rownum, 6, new QTableWidgetItem(p->frame.info));
}

void QtWidgetsApplication::handleCatcherStopped()
{
    updateButtonStatus(WAITING);
}

void QtWidgetsApplication::handleExportFile()
{
    // save file
    QString path = QFileDialog::getSaveFileName(this, "save capture file", "./", "Text files (*.pcap)");
    emit setDumperPath(path, catcher->getTmpfile());
    emit startDumperThread();
}

void QtWidgetsApplication::handleSubmitFilter()
{
    QString str = ui.lineEdit->text();
    QPalette palette;
    if (filter->validateFilter(str))
    {
        emit setFilterDev(catcher->getTmpfile());
        emit setFilterStr(str);
        palette.setColor(QPalette::Base, QColor::fromRgb(175, 255, 175));
        InitContents();
        emit startFilterThread();
    }
    else {
        palette.setColor(QPalette::Base, QColor::fromRgb(255, 175, 175));
    }
    ui.lineEdit->setPalette(palette);
}

void QtWidgetsApplication::handleFilterStopped()
{
    updateButtonStatus(WAITING);
}

void QtWidgetsApplication::handleSelectPacket()
{
    int curPkt = ui.tableWidget->currentRow();
    showPacketMsg(catcher->pkts->getPkt(curPkt));
    showPacketBytes(catcher->pkts->getPkt(curPkt));
}

void QtWidgetsApplication::handleSelectPacketItem()
{
    // get extra data
    QTreeWidgetItem* selected = ui.treeWidget->currentItem();
    u_int offset = selected->data(1, 0).value<u_int>();
    u_int length = selected->data(2, 0).value<u_int>();
    // select packet bytes
    int index = offset / 8;
    int num = length / 8 + (length % 8 == 0 ? 0 : 1);
    ui.tableWidget_2->clearSelection();
    ui.tableWidget_2->setSelectionMode(QAbstractItemView::MultiSelection);
    for (int i = 0; i < num; i++)
    {
        int row = (index + i) / 16;
        int col = (index + i) % 16;
        QTableWidgetItem* item = ui.tableWidget_2->item(row, col);
        ui.tableWidget_2->setItemSelected(item, true);
    }
    ui.tableWidget_2->setSelectionMode(QAbstractItemView::SingleSelection);
}