//
// Created by Gu Feng on 2023/3/11.
//

#ifndef LAB_1A_MAINWINDOW_H
#define LAB_1A_MAINWINDOW_H

#include "sniffer.h"
#include "shared_data.h"
#include "pcap.h"
#include <QMainWindow>
#include <QDateTime>
#include <QStandardItemModel>
#include <QLabel>
#include <vector>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void setData(DataPkt *npacket);
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_pktList_doubleClicked(const QModelIndex &index);
private:
    Ui::MainWindow *ui;
    QLabel *warning;
    pcap_if_t *allDevices; //所有网卡设备列表
    QStandardItemModel *tableModel;
    QStandardItemModel *treeModel;
    Sniffer *sniffer = nullptr;
    bpf_program fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netmask;
};


#endif //LAB_1A_MAINWINDOW_H
