#ifndef _RIPv2_H
#define _RIPv2_H

#include "ipv4.h"
#include <stdint.h>


#define RIP_PORT 520
#define RIP_MTU 504 // 504 = entry(20) * n-entries(25) + header(4)


typedef struct ripv2_entry {

    uint16_t addr_family_id;
    uint16_t route_tag;
    ipv4_addr_t ip_addr;
    ipv4_addr_t subnet_mask;
    ipv4_addr_t next_hop;
    uint32_t metric;
    
} ripv2_entry_t;

typedef struct ripv2_message {
    uint8_t command;
    uint8_t version;
    uint16_t must_be_zero;
    ripv2_entry_t entries[25];
} ripv2_message_t;

#endif