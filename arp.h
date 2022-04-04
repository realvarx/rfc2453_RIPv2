#ifndef _ARP_H
#define _ARP_H


#include "eth.h"
#include "ipv4.h"

void ipv4_addr_str(ipv4_addr_t addr, char str[]);
int ipv4_str_addr(char *str, ipv4_addr_t addr);

typedef struct arp_frame arp_frame_t;

int arp_resolve ( eth_iface_t *iface, ipv4_addr_t dest,
  mac_addr_t mac, ipv4_addr_t senderIp);

//int arp_resolve ( eth_iface_t *iface, ipv4_addr_t dest, mac_addr_t mac, ipv4_addr_t senderIp);
#endif