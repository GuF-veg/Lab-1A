//
// Created by Gu Feng on 2023/3/11.
//

#ifndef LAB_1A_SNIFFER_H
#define LAB_1A_SNIFFER_H

#include "shared_data.h"
#include "pcap.h"
#include "analyzer.h"
#include <QThread>
#include <cstring>

class Sniffer: public QThread{
Q_OBJECT
public:
    Sniffer() = default;
    void run();
    void stop();
signals:
    void sentData(DataPkt *data);
private:
    volatile bool stopped = true;
    pcap_pkthdr *header;
    const uint8_t *pkt_data;
};

#endif //LAB_1A_SNIFFER_H
