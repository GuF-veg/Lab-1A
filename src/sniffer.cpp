//
// Created by Gu Feng on 2023/3/16.
//
//#include "sniffer.h"
#include "sniffer.h"

void Sniffer::run(){
    stopped = false;
    int res;
    u_char *ppkt_data;
    while(!stopped && (res = pcap_next_ex(handle, &header, &pkt_data)) >= 0){
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
