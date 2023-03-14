//
// Created by Gu Feng on 2023/3/11.
//

#ifndef LAB_1A_SNIFFER_H
#define LAB_1A_SNIFFER_H

#include <QThread>
#include <cstring>
#include "pcap.h"

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

struct Ethernet_header
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct IP_header
{
    uint8_t header_length:4, ip_version:4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_address;
    uint32_t dst_address;
    u_int options;
};

struct ICMP_header
{
    uint8_t type;
    uint8_t code;
    uint8_t seq;
    uint8_t check;
};

struct ARP_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t opcode;
    uint8_t src_hard_address[6];
    uint8_t src_logic_address[4];
    uint8_t dst_hard_address[6];
    uint8_t dst_logic_address[4];
};

struct TCP_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t reserved:4, offset:4;
    uint8_t FIN:1,
            SYN:1,
            RST:1,
            PSH:1,
            ACK:1,
            URG:1,
            ECE:1,
            CWR:1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint option;
};

struct UDP_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct DataPkt
{
    std::string pktType;
    int time[6];
    int len;
    Ethernet_header *ethh;
    ARP_header *arph;
    IP_header *iph;
    ICMP_header *icmph;
    UDP_header *udph;
    TCP_header *tcph;
    bool isHttp;
    void *apph;
};

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
};

#endif //LAB_1A_SNIFFER_H
