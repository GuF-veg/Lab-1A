//
// Created by Gu Feng on 2023/3/11.
//

// You may need to build the project (run Qt uic code generator) to get "ui_MainWindow.h" resolved

#include "mainwindow.h"
#include "ui_MainWindow.h"

#include <QDebug>
#include <cstring>
pcap_if_t *allDevices; //所有网卡设备列表
QStandardItemModel *tableModel;
QStandardItemModel *treeModel;
std::vector<DataPkt*> allDataPkt;
std::vector<uint8_t*> dataVec;
Sniffer *sniffer = nullptr;
bpf_program fcode;
char errbuf[PCAP_ERRBUF_SIZE];
bpf_u_int32 netmask;
pcap_t *handle;
pcap_pkthdr *header;
const uint8_t *pkt_data;

MainWindow::~MainWindow() {
    delete ui;
}

MainWindow::MainWindow(QWidget *parent) :
        QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
    setFixedSize(1024, 768);
    setWindowTitle("Sniffer");
    ui->deviceSelect->addItem("请选择设备");
    if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &allDevices, errbuf) == -1)
        qDebug() << "find Devices failed.";
    QStringList devNames;
    for(pcap_if_t *dev = allDevices; dev->next != nullptr; dev = dev->next){
        devNames.emplace_back(dev->description);
    }
    ui->deviceSelect->addItems(devNames);
    tableModel = new QStandardItemModel;
    treeModel = new QStandardItemModel(ui->pktDetails);
    tableModel->setColumnCount(9);
    tableModel->setHeaderData(0, Qt::Horizontal, "Time");
    tableModel->setHeaderData(1, Qt::Horizontal, "Src. Mac");
    tableModel->setHeaderData(2, Qt::Horizontal, "Dst. Mac");
    tableModel->setHeaderData(3, Qt::Horizontal, "Src. IP");
    tableModel->setHeaderData(4, Qt::Horizontal, "Dst. IP");
    tableModel->setHeaderData(5, Qt::Horizontal, "Src. Port");
    tableModel->setHeaderData(6, Qt::Horizontal, "Dst. Port");
    tableModel->setHeaderData(7, Qt::Horizontal, "Protocol");
    tableModel->setHeaderData(8, Qt::Horizontal, "Length");
    ui->pktList->setModel(tableModel);
    ui->pktList->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->pktList->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->pktList->setColumnWidth(0, 80);
    ui->pktList->setColumnWidth(1, 150);
    ui->pktList->setColumnWidth(2, 150);
    ui->pktList->setColumnWidth(3, 150);
    ui->pktList->setColumnWidth(4, 150);
    ui->pktList->setColumnWidth(5, 80);
    ui->pktList->setColumnWidth(6, 80);
    ui->pktList->setColumnWidth(7, 80);
    ui->pktList->setColumnWidth(8, 80);
    treeModel->setHorizontalHeaderLabels(QStringList()<<QStringLiteral("Packet Details"));
    ui->pktDetails->setModel(treeModel);

    warning = new QLabel("请选择有效设备！", this);
    warning->setStyleSheet("color:#FF0000");
    warning->hide();
    ui->statusBar->addWidget(warning);
    connect(ui->startButton, &QPushButton::clicked, this, &MainWindow::on_startButton_clicked);
    connect(ui->stopButton, &QPushButton::clicked, this, &MainWindow::on_stopButton_clicked);
    connect(ui->pktList, &QTableView::doubleClicked, this, &MainWindow::on_pktList_doubleClicked);
}

void ipvalue2ipaddr(uint ip_value, char *ip_addr){
    sprintf(ip_addr, "%d.%d.%d.%d",
            (ip_value >> 24) & 0x000000ff,
            (ip_value >> 16) & 0x000000ff,
            (ip_value >> 8) & 0x000000ff,
            ip_value & 0x000000ff);
}

void MainWindow::setData(DataPkt *data) {
    int i = tableModel->rowCount();
    QString time, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, length;
    time = QDateTime::currentDateTime().toString("hh:mm:ss");
    protocol = QString(QLatin1String(data->pktType));
    char *buf = new char[80];
    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x",
            data->ethh->src[0], data->ethh->src[1], data->ethh->src[2],
            data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
    src_mac = QString(QLatin1String(buf));
    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x",
            data->ethh->dst[0], data->ethh->dst[1], data->ethh->dst[2],
            data->ethh->dst[3], data->ethh->dst[4], data->ethh->dst[5]);
    dst_mac = QString(QLatin1String(buf));
    length = QString::number(data->len);
    if(data->ethh->type == 0x0806){
        sprintf(buf, "%d.%d.%d.%d",
                data->arph->src_logic_address[0], data->arph->src_logic_address[1],
                data->arph->src_logic_address[2], data->arph->src_logic_address[3]);
        src_ip = QString(QLatin1String(buf));
        sprintf(buf, "%d.%d.%d.%d",
                data->arph->dst_logic_address[0], data->arph->dst_logic_address[1],
                data->arph->dst_logic_address[2], data->arph->dst_logic_address[3]);
        dst_ip = QString(QLatin1String(buf));
    }
    else if(data->ethh->type == 0x0800){
        ipvalue2ipaddr(ntohl(data->iph->src_address), buf);
        src_ip = QString(QLatin1String(buf));
        ipvalue2ipaddr(ntohl(data->iph->dst_address), buf);
        dst_ip = QString(QLatin1String(buf));
    }
    if(data->pktType == "UDP"){
        src_port = QString::number(data->udph->src_port);
        dst_port = QString::number(data->udph->dst_port);
    }
    else if(data->pktType == "TCP" || data->pktType == "HTTP"){
        src_port = QString::number(data->tcph->src_port);
        dst_port = QString::number(data->tcph->dst_port);
    }
    else{
        src_port = QString("Nan");
        dst_port = QString("Nan");
    }
    tableModel->setItem(i, 0, new QStandardItem(time));
    tableModel->setItem(i, 1, new QStandardItem(src_mac));
    tableModel->setItem(i, 2, new QStandardItem(dst_mac));
    tableModel->setItem(i, 3, new QStandardItem(src_ip));
    tableModel->setItem(i, 4, new QStandardItem(dst_ip));
    tableModel->setItem(i, 5, new QStandardItem(src_port));
    tableModel->setItem(i, 6, new QStandardItem(dst_port));
    tableModel->setItem(i, 7, new QStandardItem(protocol));
    tableModel->setItem(i, 8, new QStandardItem(length));
    delete []buf;
}

void MainWindow::on_startButton_clicked() {
    tableModel->removeRows(0, tableModel->rowCount());
    treeModel->clear();
    treeModel->setHorizontalHeaderLabels(QStringList()<<QStringLiteral("Packet Details"));
    ui->pktInBinary->clear();
    allDataPkt.clear();
    dataVec.clear();
    pcap_if_t *dev = allDevices;
    if(ui->deviceSelect->currentIndex() == 0){
        warning->show();
        return;
    }
    warning->hide();
    for(int i = 0; i < ui->deviceSelect->currentIndex()-1; i++)
        dev = dev->next;
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr){
        qDebug("Couldn't open device.");
        return;
    }
    qDebug(dev->description);
    if(pcap_datalink(handle) != DLT_EN10MB){
        qDebug("不适用非以太网的网络");
        return;
    }
    if(dev->addresses != nullptr)
        netmask = ((sockaddr_in*)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask = 0xffffff;
    std::string fstr = ui->filterRule->text().toStdString();
    const char* c_s = fstr.c_str();
    if(pcap_compile(handle, &fcode, c_s, 1, netmask) < 0){
        qDebug("编译过滤器失败");
        return;
    }
    if(pcap_setfilter(handle, &fcode) < 0){
        qDebug("语法错误，无法设置过滤器");
        return;
    }
    ui->startButton->setDisabled(true);
    sniffer = new Sniffer;
    connect(sniffer, &Sniffer::sentData, this, &MainWindow::setData);
    sniffer->start();
}

void MainWindow::on_stopButton_clicked() {
    warning->hide();
    if(sniffer != nullptr)
        sniffer->stop();
    ui->startButton->setEnabled(true);
}

void Sniffer::run() {
    stopped = false;
    int res;
    u_char *ppkt_data;
    while(stopped != true && (res = pcap_next_ex(handle, &header, &pkt_data)) >= 0){
        if(res == 0)
            continue;
        DataPkt *data = new DataPkt;
        data->isHttp = false;
        memset(data, 0, sizeof(DataPkt));
        data->len = header->len;
        analyze_ethernet_frame(pkt_data, data);
        emit sentData(data);
        ppkt_data = new u_char[header->len];
        memcpy(ppkt_data, pkt_data, header->len);
        allDataPkt.emplace_back(data);
        dataVec.emplace_back(ppkt_data);
    }
}

void Sniffer::stop() {
    stopped = true;
}

void MainWindow::on_pktList_doubleClicked(const QModelIndex &index)
{
    int row=index.row();
    QString src_mac,dest_mac;
    char* buf=(char*)malloc(108*sizeof(char));
    sprintf(buf,"%02x-%02x-%02x-%02x-%02x-%02x",allDataPkt[row]->ethh->src[0],allDataPkt[row]->ethh->src[1],allDataPkt[row]->ethh->src[2],allDataPkt[row]->ethh->src[3],allDataPkt[row]->ethh->src[4],allDataPkt[row]->ethh->src[5]);
    src_mac=QString(QLatin1String(buf));
    sprintf(buf,"%02x-%02x-%02x-%02x-%02x-%02x",allDataPkt[row]->ethh->dst[0],allDataPkt[row]->ethh->dst[1],allDataPkt[row]->ethh->dst[2],allDataPkt[row]->ethh->dst[3],allDataPkt[row]->ethh->dst[4],allDataPkt[row]->ethh->dst[5]);
    dest_mac=QString(QLatin1String(buf));

    ui->pktInBinary->setText("");
    int i=0,j = 0,rowcount;char ch;
    char tempbuf[8];strcpy(tempbuf,"");strcpy(buf,"");
    int size_pkt=allDataPkt[row]->len;u_char* pkt=dataVec[row];
    for(i= 0;i<size_pkt;i+=16)
    {
        sprintf(tempbuf,"%04x: ",i);
        strcat(buf,tempbuf);
        rowcount= (size_pkt-i) > 16 ? 16 : (size_pkt-i);
        for(j = 0; j < rowcount; j++){
            sprintf(tempbuf,"%02x ",pkt[i+j]);strcat(buf,tempbuf);
        }

        for(j=rowcount;j<16;j++){
            strcpy(tempbuf,"   ");strcat(buf,tempbuf);
        }
        strcpy(tempbuf,"   ");strcat(buf,tempbuf);
        for(j = 0; j < rowcount; j++){
            ch = pkt[i+j];
            ch = isprint(ch) ? ch : '.';
            sprintf(tempbuf,"%c ",ch);
            strcat(buf,tempbuf);
        }
        strcat(buf,"\n");
        ui->pktInBinary->append(buf);
        strcpy(buf,"");
        if(rowcount<16)
            break;
    }
    QString h="捕获的第"+QString::number(row+1)+"个数据包，封装的协议类型为"+allDataPkt[row]->pktType.c_str()+"协议";
    QStandardItem *head=new QStandardItem(h);
    QStandardItem *ethdata=new QStandardItem("链路层数据");
    QStandardItem *arpdata=new QStandardItem("ARP协议头");
    QStandardItem *ipdata=new QStandardItem("IP协议头");
    QStandardItem *tcpdata=new QStandardItem("TCP协议头");
    QStandardItem *udpdata=new QStandardItem("UDP协议头");
    QStandardItem *icmpdata=new QStandardItem("ICMP协议头");
    treeModel->setItem(0,head);
    head->setChild(0,ethdata);
    ethdata->setChild(0,new QStandardItem("源MAC："+src_mac));
    ethdata->setChild(1,new QStandardItem("目的MAC："+dest_mac));
    sprintf(tempbuf,"0x%04x",allDataPkt[row]->ethh->type);
    ethdata->setChild(2,new QStandardItem("类型："+QString(QLatin1String(tempbuf))));
    QModelIndex current_index;
    switch (allDataPkt[row]->ethh->type) {
        case 0x0806:
            head->setChild(1,arpdata);
            arpdata->setChild(0,new QStandardItem("硬件类型："+QString::number(allDataPkt[row]->arph->hardware_type)));
            arpdata->setChild(1,new QStandardItem("协议类型："+QString::number(allDataPkt[row]->arph->protocol_type)));
            arpdata->setChild(2,new QStandardItem("硬件地址长度："+QString::number(allDataPkt[row]->arph->hardware_length)));
            arpdata->setChild(3,new QStandardItem("协议地址长度："+QString::number(allDataPkt[row]->arph->protocol_length)));
            sprintf(buf,"%0d.%d.%d.%d",allDataPkt[row]->arph->src_logic_address[0],allDataPkt[row]->arph->src_logic_address[1],allDataPkt[row]->arph->src_logic_address[2],allDataPkt[row]->arph->src_logic_address[3]);
            arpdata->setChild(4,new QStandardItem("发送方IP："+QString(QLatin1String(buf))));
            sprintf(buf,"%0d.%d.%d.%d",allDataPkt[row]->arph->dst_logic_address[0],allDataPkt[row]->arph->dst_logic_address[1],allDataPkt[row]->arph->dst_logic_address[2],allDataPkt[row]->arph->dst_logic_address[3]);
            arpdata->setChild(5,new QStandardItem("接受方IP："+QString(QLatin1String(buf))));
            break;
        case 0x0800:
            head->setChild(1,ipdata);
            ipdata->setChild(0,new QStandardItem("版本号："+QString::number(allDataPkt[row]->iph->ip_version)));
            ipdata->setChild(1,new QStandardItem("头部长度："+QString::number(allDataPkt[row]->iph->header_length)));
            ipdata->setChild(2,new QStandardItem("服务类型TOS："+QString::number(allDataPkt[row]->iph->tos)));
            ipdata->setChild(3,new QStandardItem("总长度："+QString::number(allDataPkt[row]->iph->total_length)));
            sprintf(tempbuf,"0x%04x",allDataPkt[row]->iph->identification);
            ipdata->setChild(4,new QStandardItem("标识："+QString(QLatin1String(tempbuf))));
            ipdata->setChild(5,new QStandardItem("位偏移："+QString::number(allDataPkt[row]->iph->offset)));
            ipdata->setChild(6,new QStandardItem("生存时间TTL："+QString::number(allDataPkt[row]->iph->ttl)));
            ipdata->setChild(7,new QStandardItem("协议："+QString::number(allDataPkt[row]->iph->protocol)));
            ipdata->setChild(8,new QStandardItem("头部校验和："+QString::number(allDataPkt[row]->iph->checksum)));
            current_index=tableModel->index(row,1);
            ipdata->setChild(9,new QStandardItem("源IP："+tableModel->data(current_index).toString()));
            current_index=tableModel->index(row,2);
            ipdata->setChild(10,new QStandardItem("目的IP："+tableModel->data(current_index).toString()));
            switch (allDataPkt[row]->iph->protocol) {
                case PROTO_TCP:
                    head->setChild(2,tcpdata);
                    tcpdata->setChild(0,new QStandardItem("源端口："+QString::number(allDataPkt[row]->tcph->src_port)));
                    tcpdata->setChild(1,new QStandardItem("目的端口："+QString::number(allDataPkt[row]->tcph->dst_port)));
                    tcpdata->setChild(2,new QStandardItem("序列号："+QString::number(allDataPkt[row]->tcph->seq)));
                    tcpdata->setChild(3,new QStandardItem("确认序列号："+QString::number(allDataPkt[row]->tcph->ack)));
                    tcpdata->setChild(4,new QStandardItem("窗口大小："+QString::number(allDataPkt[row]->tcph->window)));
                    tcpdata->setChild(5,new QStandardItem("SYN："+QString::number(allDataPkt[row]->tcph->SYN)));
                    tcpdata->setChild(6,new QStandardItem("ACK："+QString::number(allDataPkt[row]->tcph->ACK)));
                    tcpdata->setChild(7,new QStandardItem("FIN："+QString::number(allDataPkt[row]->tcph->FIN)));
                    tcpdata->setChild(8,new QStandardItem("校验和："+QString::number(allDataPkt[row]->tcph->checksum)));
                    tcpdata->setChild(9,new QStandardItem("紧急指针："+QString::number(allDataPkt[row]->tcph->urgent_pointer)));
                    break;
                case PROTO_UDP:
                    head->setChild(2,udpdata);
                    udpdata->setChild(0,new QStandardItem("源端口："+QString::number(allDataPkt[row]->udph->src_port)));
                    udpdata->setChild(1,new QStandardItem("目的端口："+QString::number(allDataPkt[row]->udph->dst_port)));
                    udpdata->setChild(2,new QStandardItem("数据报长度："+QString::number(allDataPkt[row]->udph->length)));
                    udpdata->setChild(3,new QStandardItem("校验和："+QString::number(allDataPkt[row]->udph->checksum)));
                    break;
                case PROTO_ICMP:
                    head->setChild(2,icmpdata);
                    icmpdata->setChild(0,new QStandardItem("类型："+QString::number(allDataPkt[row]->icmph->type)));
                    icmpdata->setChild(1,new QStandardItem("代码："+QString::number(allDataPkt[row]->icmph->code)));
                    icmpdata->setChild(2,new QStandardItem("序列号："+QString::number(allDataPkt[row]->icmph->seq)));
                    icmpdata->setChild(3,new QStandardItem("校验和："+QString::number(allDataPkt[row]->icmph->check)));
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
}