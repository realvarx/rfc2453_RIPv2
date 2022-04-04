#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "ipv4.h"
#include "udp.h"

#define CLIENT_PORT 9373

int main(int argc, char *argv[])
{

    char* host;
	uint16_t port;
    //int bufsize;
    int err;


    switch (argc) {
	case 3:
		host = argv[1];
		port = atoi(argv[2]);
        //bufsize = atoi(argv[3]);
		break;
	default:
		fprintf(stderr, "usage: %s <host> <port>\n", argv[0]);
		exit(1);
    }

    ipv4_addr_t ip_dst;
    ipv4_str_addr(host, ip_dst);

    puts("ANTES DEL OPEN");
    printf("ANTES DEL OPEN");

    udp_layer_t *layer = udp_open("ipv4_config_client.txt",
                        "ipv4_route_table_client.txt", CLIENT_PORT);

    unsigned char payload[UDP_MTU];

    puts("ANTES DEL FOR");

    int i;
    for (i=0; i<UDP_MTU; i++) {
    payload[i] = (unsigned char) i;
    }

    puts("ANTES DEL SEND");

    err = udp_send(layer, port, ip_dst, payload, UDP_MTU);
    if(err == -1) {
        exit(-1);
    }

    uint16_t recvFromPort;
    ipv4_addr_t recvFromIp;
    unsigned char recvFrame[UDP_MTU];

    puts("ANTES DEL RECV");

    err = udp_recv(layer, &recvFromPort, recvFrame, recvFromIp, UDP_MTU, 5000);

    if(err == -1) {
        exit(-1);
    }

    printf("Packet has been recieved from : %s\n", recvFromIp);

    print_pkt(recvFrame, UDP_MTU, 0);

    puts("ANTES DE ACABAR");

    return 0;
}
