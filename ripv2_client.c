#include <stdint.h>

#include "ripv2.h"
#include "ripv2_route_table.h"
#include "udp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <timerms.h>
#include <string.h>
#include <libgen.h>
#include <arpa/inet.h>


int main(int argc, char *argv[])
{

    char* host;
	uint16_t port = RIP_PORT;
    int length;


    switch (argc) {
	case 2:
		host = argv[1];
		break;
	default:
		fprintf(stderr, "usage: %s <host> \n", argv[0]);
		exit(1);
    }

    ipv4_addr_t ip_dst;
    ipv4_str_addr(host, ip_dst);

    puts("ANTES DEL OPEN");
    printf("ANTES DEL OPEN");

    udp_layer_t *layer = udp_open("ipv4_config_client.txt",
                        "ipv4_route_table_client.txt", RIP_PORT);


    ripv2_entry_t zero_entry;
    zero_entry.addr_family_id = 0x00;
    zero_entry.route_tag = 0x00;
    memcpy(zero_entry.subnet_mask, IPv4_ZERO_ADDR, IPv4_ADDR_SIZE); // Subnet 0.0.0.0
    memcpy(zero_entry.ip_addr, IPv4_ZERO_ADDR, IPv4_ADDR_SIZE);
    memcpy(zero_entry.next_hop, IPv4_ZERO_ADDR, IPv4_ADDR_SIZE);    // Nexthop como 0.0.0.0
    zero_entry.metric = htonl(16);  // Métrica a infinito

    ripv2_message_t rip_request;

    rip_request.command = 0x01;
    rip_request.must_be_zero = 0x0000;
    rip_request.version = 0x02;
    rip_request.entries[0] = zero_entry;

    // 24 = header(4) + rip_entry(20)

    length = udp_send(layer, port, ip_dst, (unsigned char *)&rip_request, 24);
    if(length == -1) {
        exit(-1);
    }

    uint16_t recvFromPort;
    ipv4_addr_t recvFromIp;

    unsigned char recvFrame[RIP_MTU];

    length = udp_recv(layer, &recvFromPort, recvFrame, recvFromIp, RIP_MTU, 2000);

    if(length == -1) {
        printf("RIPv2 : recv error");
        exit(-1);
    }

    if(length == 0){
        printf("RIPV2 : recv timeout");
        exit(0);
    }

    printf("Packet has been recieved from : %s\n", recvFromIp);

    ripv2_message_t *rip_response = (ripv2_message_t*) recvFrame;

    int n_entries = (length - 4) / 20;

    printf("++++++++++++++++++++++++++++++++++++++\n");

    for(int i = 0; i<n_entries; i++){

        char ip_str[15];
        
        printf("Address Family : %d\n", ntohs(rip_response->entries[i].addr_family_id));
        printf("Route Tag : %d\n", ntohs(rip_response->entries[i].route_tag));
         ipv4_addr_str(rip_response->entries[i].ip_addr, ip_str);
        printf("IP Address : %s\n", ip_str);
         ipv4_addr_str(rip_response->entries[i].subnet_mask, ip_str);
        printf("Subnet Mask : %s\n", ip_str);
         ipv4_addr_str(rip_response->entries[i].next_hop, ip_str);
        printf("Next Hop : %s\n", ip_str);
        printf("Metric : %d\n", ntohl(rip_response->entries[i].metric));
        printf("++++++++++++++++++++++++++++++++++++++\n");

        //rip_response->entries[i];
    }

    //print_pkt(recvFrame, RIP_MTU, 0);

    //puts("ANTES DE ACABAR");

    int err = udp_close(layer);
    if(err == -1) {
        printf("RIPv2 : error closing layer");
        return -1;
    }

    return 0;
}