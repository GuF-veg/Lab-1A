//
// Created by Gu Feng on 2023/3/16.
//

#ifndef LAB_1A_SHARED_DATA_H
#define LAB_1A_SHARED_DATA_H
#include "analyzer.h"
#include "pcap.h"
extern std::vector<DataPkt*> allDataPkt;
extern std::vector<uint8_t*> dataVec;
extern pcap_t *handle;
#endif //LAB_1A_SHARED_DATA_H
