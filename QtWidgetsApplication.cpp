#include "QtWidgetsApplication.h"

QtWidgetsApplication::QtWidgetsApplication(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    connect(ui.comboBox, static_cast<void (QComboBox::*)(int)>(& QComboBox::currentIndexChanged), this, &QtWidgetsApplication::handleSelectDev);
    connect(ui.pushButtonStart, &QPushButton::clicked, this, &QtWidgetsApplication::handleStartCatcher);
    connect(ui.pushButtonEnd, &QPushButton::clicked, this, &QtWidgetsApplication::handleStopCatcher);
    connect(ui.pushButtonImport, &QPushButton::clicked, this, &QtWidgetsApplication::handleImportFile);
    connect(ui.pushButtonExport, &QPushButton::clicked, this, &QtWidgetsApplication::handleExportFile);
    connect(ui.lineEdit, &QLineEdit::returnPressed, this, &QtWidgetsApplication::handleSubmitFilter);
    connect(ui.tableWidget, &QTableWidget::itemSelectionChanged, this, &QtWidgetsApplication::handleSelectPacket);
    connect(ui.treeWidget, &QTreeWidget::itemSelectionChanged, this, &QtWidgetsApplication::handleSelectPacketItem);

    catcher = new PacketCatcher;
    InitComboBox();
    InitLineEdit();
    InitTableStyle();
    InitTreeStyle();
    InitTable2Style();

    // create the catcher thread
    catcher->moveToThread(&catcherThread);
    connect(&catcherThread, &QThread::finished, &catcherThread, &QThread::deleteLater);
    connect(&catcherThread, &QThread::finished, catcher, &QObject::deleteLater);
    connect(this, &QtWidgetsApplication::startCatcherThread, catcher, &PacketCatcher::startCapture);
    connect(this, &QtWidgetsApplication::stopCatcherThread, catcher, &PacketCatcher::stopCapture);
    connect(this, &QtWidgetsApplication::addCatcherDev, catcher, &PacketCatcher::addLocalDev);
    connect(this, &QtWidgetsApplication::changeCatcherDev, catcher, &PacketCatcher::setCurDev);
    connect(this, &QtWidgetsApplication::saveCatcherFile, catcher, &PacketCatcher::saveFile);
    connect(this, &QtWidgetsApplication::setCatcherFilter, catcher, &PacketCatcher::setFilter);
    connect(this, &QtWidgetsApplication::startCatcherFilter, catcher, &PacketCatcher::startFilter);
    connect(catcher, &PacketCatcher::newPacketCaptured, this, &QtWidgetsApplication::handlePacketCaptured);
    connect(catcher, &PacketCatcher::captureStopped, this, &QtWidgetsApplication::handleCatcherStopped);
    catcherThread.start();
}

QtWidgetsApplication::~QtWidgetsApplication()
{
    emit stopCatcherThread();
    catcherThread.quit();
    catcherThread.wait();
}

void QtWidgetsApplication::InitComboBox()
{
    ui.comboBox->clear();
    ui.comboBox->addItem("select dev");
    emit changeCatcherDev(0);
    for (auto dev = catcher->m_devstrlist.begin(); dev != catcher->m_devstrlist.end(); dev++)
    {
        ui.comboBox->addItem((*dev)->desc);
    }
}

void QtWidgetsApplication::InitLineEdit()
{
    updateLineStatus(NOEDIT);
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

bool QtWidgetsApplication::isContentEmpty()
{
    return catcher->m_pkts.size() == 0;
}

bool QtWidgetsApplication::isDevSelected()
{
    return ui.comboBox->currentIndex() > 0;
}

void QtWidgetsApplication::updateButtonStatus(ButtonStatus s)
{
    switch (s)
    {
    case WAITING:
        ui.pushButtonStart->setEnabled(
            isDevSelected()
        );
        ui.pushButtonEnd->setEnabled(false);
        ui.pushButtonImport->setEnabled(true);
        ui.pushButtonExport->setEnabled(
            !isContentEmpty()
        );
        ui.comboBox->setEnabled(true);
        break;
    case CAPTURING:
        ui.pushButtonStart->setEnabled(false);
        ui.pushButtonEnd->setEnabled(true);
        ui.pushButtonImport->setEnabled(false);
        ui.pushButtonExport->setEnabled(false);
        ui.comboBox->setEnabled(false);
        break;
    }
}

void QtWidgetsApplication::updateLineStatus(LineStatus s)
{
    //switch (s)
    //{
    //case EDIT:
    //    ui.lineEdit->setEnabled(true);
    //    break;
    //case NOEDIT:
    //    ui.lineEdit->setEnabled(false);
    //    break;
    //}
}

void QtWidgetsApplication::showPacketMsg(Packet* p)
{
    ui.treeWidget->clear();
    // frame msg
    QTreeWidgetItem* frame = new QTreeWidgetItem({ "frame" });
    frame->addChild(new QTreeWidgetItem({ "frame number:  " + QString::number(p->frame_msg.num) }));
    frame->addChild(new QTreeWidgetItem({ "frame length:  " + QString::number(p->frame_msg.length) + "bytes"}));
    frame->addChild(new QTreeWidgetItem({ "capture time:  " + p->frame_msg.time.toString("yyyy-MM-dd mm:ss:zzz")}));
    frame->addChild(new QTreeWidgetItem({ "upper protocol:  " + p->frame_msg.protocol}));
    if (p->frame_msg.stream_index != -1) frame->addChild(new QTreeWidgetItem({ p->frame_msg.protocol + " stream index:  " + QString::number(p->frame_msg.stream_index)}));
    ui.treeWidget->addTopLevelItem(frame);
    // protocols
    int i = 0;
    for (auto protocol_msg : p->protocols)
    {
        QTreeWidgetItem* protocol = new QTreeWidgetItem({ protocol_msg->name });
        int j = 0;
        for (auto protocol_item : protocol_msg->items)
        {
            QTreeWidgetItem* item = new QTreeWidgetItem({ protocol_item->name + ":  " + protocol_item->desc});
            if (!protocol_item->children.isEmpty())
            {
                int k = 0;
                for (auto child : protocol_item->children)
                {
                    QTreeWidgetItem* c = new QTreeWidgetItem({ child->name + ":  " + child->desc });
                    item->setData(1, 0, p->protocols[i]->offset * 8 + p->protocols[i]->items[j]->offset + p->protocols[i]->items[j]->children[k]->offset);
                    item->setData(2, 0, p->protocols[i]->items[j]->children[k]->length);
                    item->addChild(c);
                }
                k++;
            }
            // store extra data, bit
            item->setData(1, 0, p->protocols[i]->offset * 8 + p->protocols[i]->items[j]->offset);
            item->setData(2, 0, p->protocols[i]->items[j]->length);
            protocol->addChild(item);
            j++;
        }
        ui.treeWidget->addTopLevelItem(protocol);
        // store extra data, byte to bit
        protocol->setData(1, 0, p->protocols[i]->offset * 8);
        protocol->setData(2, 0, p->protocols[i]->length * 8);
        i++;
    }
}

void QtWidgetsApplication::showPacketBytes(Packet* p)
{
    ui.tableWidget_2->clear();
    int length = p->frame_msg.length;
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
    if (index != 0)
    {
        // 0th is "select dev"
        emit changeCatcherDev(index - 1);
        updateButtonStatus(WAITING);
        updateLineStatus(EDIT);
    }
}

void QtWidgetsApplication::handleStartCatcher()
{
    updateButtonStatus(CAPTURING);
    updateLineStatus(NOEDIT);
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

void QtWidgetsApplication::handleExportFile()
{
    // save file
    QString path = QFileDialog::getSaveFileName(this, "save capture file", "./", "Text files (*.pcap)");
    emit saveCatcherFile(path);
}

void QtWidgetsApplication::handleSubmitFilter()
{
    QString str = ui.lineEdit->text();
    QPalette palette;
    if (catcher->validateFilter(str))
    {
        emit setCatcherFilter(str);
        palette.setColor(QPalette::Base, QColor::fromRgb(175, 255, 175));
        InitContents();
        emit startCatcherFilter();
    }
    else {
        palette.setColor(QPalette::Base, QColor::fromRgb(255, 175, 175));
    }
    ui.lineEdit->setPalette(palette);
}

void QtWidgetsApplication::handlePacketCaptured(Packet *p)
{
    int rownum = ui.tableWidget->rowCount();
    ui.tableWidget->setRowCount(rownum + 1);
    ui.tableWidget->setItem(rownum, 0, new QTableWidgetItem(QString::number(p->frame_msg.num)));
    ui.tableWidget->setItem(rownum, 1, new QTableWidgetItem(p->frame_msg.time.toString("mm:ss:zzz")));
    ui.tableWidget->setItem(rownum, 2, new QTableWidgetItem(p->frame_msg.src));
    ui.tableWidget->setItem(rownum, 3, new QTableWidgetItem(p->frame_msg.des));
    ui.tableWidget->setItem(rownum, 4, new QTableWidgetItem(p->frame_msg.protocol));
    ui.tableWidget->setItem(rownum, 5, new QTableWidgetItem(QString::number(p->frame_msg.length)));
    ui.tableWidget->setItem(rownum, 6, new QTableWidgetItem(p->frame_msg.info));
}

void QtWidgetsApplication::handleCatcherStopped()
{
    updateButtonStatus(WAITING);
    updateLineStatus(EDIT);
}

void QtWidgetsApplication::handleSelectPacket()
{
    int curPacket = ui.tableWidget->currentRow();
    showPacketMsg(catcher->m_pkts[curPacket]);
    showPacketBytes(catcher->m_pkts[curPacket]);
}

void QtWidgetsApplication::handleSelectPacketItem()
{
    // get extra data
    QTreeWidgetItem* selected = ui.treeWidget->currentItem();
    u_int offset = selected->data(1, 0).value<u_int>();
    u_int length = selected->data(2, 0).value<u_int>();
    // select packet bytes
    int index = offset / 8 - (offset % 8 == 0 ? 0 : 1);
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