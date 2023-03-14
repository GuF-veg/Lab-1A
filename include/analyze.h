//
// Created by Gu Feng on 2023/3/11.
//

#ifndef LAB_1A_ANALYZE_H
#define LAB_1A_ANALYZE_H

#include "sniffer.h"
#include <QDebug>

extern bool analyze_ethernet_frame(const uint8_t* pkt,DataPkt * data);
extern bool analyze_arp(const uint8_t* pkt,DataPkt *data);
extern bool analyze_ip(const uint8_t* pkt,DataPkt *data);
extern bool analyze_icmp(const uint8_t* pkt,DataPkt *data);
extern bool analyze_tcp(const uint8_t* pkt,DataPkt *data);
extern bool analyze_udp(const uint8_t* pkt,DataPkt *data);

#endif //LAB_1A_ANALYZE_H
