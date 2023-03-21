//
// Created by Gu Feng on 2023/3/11.
//
#include "analyzer.h"

bool analyze_arp(const uint8_t* pkt,DataPkt *data);
bool analyze_ip(const uint8_t* pkt,DataPkt *data);
bool analyze_icmp(const uint8_t* pkt,DataPkt *data);
bool analyze_tcp(const uint8_t* pkt,DataPkt *data);
bool analyze_udp(const uint8_t* pkt,DataPkt *data);

bool analyze_ethernet_frame(const uint8_t* pkt, DataPkt* data){
    auto* ethh = (Ethernet_header*)pkt;
    data->ethh = new Ethernet_header;
    if(data->ethh == nullptr)
        return false;
    for(int i = 0; i < 6; i++){
        data->ethh->dst[i] = ethh->dst[i];
        data->ethh->src[i] = ethh->src[i];
    }
    data->ethh->type = ntohs(ethh->type);
    if(data->ethh->type == 0x0806){
        return analyze_arp(pkt+14, data);
    }
    else if(data->ethh->type == 0x0800){
        return analyze_ip(pkt+14, data);
    }
    else
        return false;
}

bool analyze_arp(const uint8_t * pkt,DataPkt *data){
    auto *arph = (ARP_header*) pkt;
    data->arph = new ARP_header;
    if(data->arph == nullptr)
        return false;
    data->arph->hardware_type = ntohs(arph->hardware_type);
    data->arph->protocol_type = ntohs(arph->protocol_type);
    data->arph->hardware_length = arph->hardware_length;
    data->arph->protocol_length = arph->protocol_length;
    data->arph->opcode = ntohs(arph->opcode);
    std::memcpy(&data->arph->src_hard_address, &arph->src_hard_address, 6);
    std::memcpy(&data->arph->dst_hard_address, &arph->dst_hard_address, 6);
    std::memcpy(&data->arph->src_logic_address, &arph->src_logic_address, 4);
    std::memcpy(&data->arph->dst_logic_address, &arph->dst_logic_address, 4);
    data->pktType = "ARP";
    return true;
}

bool analyze_ip(const uint8_t* pkt,DataPkt *data){
    auto *iph = (IP_header*)pkt;
    data->iph = new IP_header;
    if(data->iph == nullptr)
        return false;
    data->iph->header_length = iph->header_length;
    data->iph->ip_version = iph->ip_version;
    data->iph->tos = iph->tos;
    data->iph->total_length = ntohs(iph->total_length);
    data->iph->identification = iph->identification;
    data->iph->offset = iph->offset;
    data->iph->ttl = iph->ttl;
    data->iph->protocol = iph->protocol;
    data->iph->checksum = iph->checksum;
    data->iph->src_address = iph->src_address;
    data->iph->dst_address = iph->dst_address;
    data->iph->options = iph->options;
    int iph_length = iph->header_length * 4;
    if(iph->protocol == PROTO_ICMP)
        return analyze_icmp(pkt+iph_length, data);
    else if(iph->protocol == PROTO_TCP)
        return analyze_tcp(pkt+iph_length, data);
    else if(iph->protocol == PROTO_UDP)
        return analyze_udp(pkt+iph_length, data);
    else
        return false;
}

bool analyze_icmp(const uint8_t* pkt,DataPkt *data){
    auto *icmph = (ICMP_header*) pkt;
    data->icmph = new ICMP_header;
    if(data->icmph == nullptr)
        return false;
    data->icmph->type = icmph->type;
    data->icmph->code = icmph->code;
    data->icmph->seq = icmph->seq;
    data->icmph->check = icmph->check;
    data->pktType = "ICMP";
    return true;
}

bool analyze_tcp(const uint8_t* pkt,DataPkt *data){
    auto *tcph = (TCP_header*) pkt;
    data->tcph = new TCP_header;
    if(data->tcph == nullptr)
        return false;
    data->tcph->src_port = ntohs(tcph->src_port);
    data->tcph->dst_port = ntohs(tcph->dst_port);
    data->tcph->seq = tcph->seq;
    data->tcph->ack = tcph->ack;
    data->tcph->reserved = tcph->reserved;
    data->tcph->offset = tcph->offset;
    data->tcph->FIN = tcph->FIN;
    data->tcph->SYN = tcph->SYN;
    data->tcph->RST = tcph->RST;
    data->tcph->PSH = tcph->PSH;
    data->tcph->ACK = tcph->ACK;
    data->tcph->URG = tcph->URG;
    data->tcph->ECE = tcph->ECE;
    data->tcph->CWR = tcph->CWR;
    data->tcph->window = tcph->window;
    data->tcph->checksum = tcph->checksum;
    data->tcph->urgent_pointer = tcph->urgent_pointer;
    data->tcph->option = tcph->option;
    if(data->tcph->dst_port == 80 || data->tcph->src_port == 80)
        data->pktType = "HTTP";
    else
        data->pktType = "TCP";
    return true;
}

bool analyze_udp(const uint8_t* pkt,DataPkt *data){
    auto *udph = (UDP_header*) pkt;
    data->udph = new UDP_header;
    if(data->udph == nullptr)
        return false;
    data->udph->src_port = ntohs(udph->src_port);
    data->udph->dst_port = ntohs(udph->dst_port);
    data->udph->length = ntohs(udph->length);
    data->udph->checksum = udph->checksum;
    data->pktType = "UDP";
    return true;
}