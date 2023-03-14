//
// Created by Gu Feng on 2023/3/11.
//

#ifndef LAB_1A_MAINWINDOW_H
#define LAB_1A_MAINWINDOW_H

#include "pcap.h"
#include "sniffer.h"
#include "analyze.h"
#include <QMainWindow>
#include <QDateTime>
#include <QStandardItemModel>
#include <QLabel>
#include <vector>
#include <winsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;
    void initCaps();
    void setData(DataPkt *npacket);
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_pktList_doubleClicked(const QModelIndex &index);
//    void run_sniffer();
//    void stop_sniffer();
//signals:
//    void sentData(DataPkt *data);
private:
    Ui::MainWindow *ui;
    QLabel *warning;
};


#endif //LAB_1A_MAINWINDOW_H
