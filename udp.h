#ifndef _UDP_H
#define _UDP_H

//#include <stdint.h>
#include "ipv4.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <timerms.h>

#define PORT 6665
#define UDP_HEADER_SIZE 8
#define UDP_MTU 1472
// UDP HEADER SIZE = 16

typedef struct udp_layer udp_layer_t;

char *udp_getIfaceName(udp_layer_t *layer);

udp_layer_t *udp_open(char * file_conf, char * file_conf_route, uint16_t port);

int udp_close(udp_layer_t *layer);

int udp_send(udp_layer_t * layer, uint16_t dest_port, ipv4_addr_t dst,
  unsigned char * payload, int payload_len);

int udp_recv(udp_layer_t * layer, uint16_t *src_port, unsigned char buffer[],
              ipv4_addr_t sender, int buf_len, long int timeout);

#endif
