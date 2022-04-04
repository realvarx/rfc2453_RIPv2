#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "ipv4.h"
#include "udp.h"

int main(int argc, char *argv[])
{

    //char* host;
	uint16_t port;
    //int err;
    

    switch (argc) {
	case 2:
		//host = argv[1];
		port = atoi(argv[1]);
        //bufsize = atoi(argv[3]);
		break;
	default:
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
    }

    udp_layer_t *layer = udp_open("ipv4_config_server.txt",
                        "ipv4_route_table_server.txt", port);

    unsigned char buffer[UDP_MTU];
    ipv4_addr_t receivedIp;

    uint16_t senderPort;

    while(1) {
        if (udp_recv(layer, &senderPort, buffer, receivedIp, UDP_MTU, -1) == -1) {
            exit(-1);
        }

        //printf("EL SENDER PORT ES : %d\n", senderPort);

        char strReceivedIp[IPv4_STR_MAX_LENGTH];

        ipv4_addr_str(receivedIp, strReceivedIp);
        printf("Information recieved from %s\n", strReceivedIp);
        if(udp_send(layer, senderPort, receivedIp, buffer, UDP_MTU) == -1) {
            exit(-1);
            puts("Information has been sent back to client");
        }
    }

    return 0;





    /*

    puts("ANTES DEL OPEN");
    printf("ANTES DEL OPEN");

    udp_layer_t *layer = udp_open("ipv4_config_server.txt", 
                        "ipv4_route_table_server.txt", port);

    puts("DESPUES DEL OPEN");

    unsigned char buffer[UDP_MTU];

    uint16_t recvFromPort;
    ipv4_addr_t recvFromIp;

    puts("ANTES DEL RECV");

    err = udp_recv(layer, &recvFromPort, buffer, recvFromIp, UDP_MTU, 10000);
    if(err == -1) {
        exit(-1);
    }

    printf("Packet has been recieved from : %s\n", recvFromIp);

    print_pkt(buffer, UDP_MTU, 0);

    puts("ANTES DEL SEND");

    err = udp_send(layer, recvFromPort, recvFromIp, buffer, UDP_MTU);
    if(err == -1) {
        exit(-1);
    }

    puts("ANTES DE ACABAR");
    
    return 0;

    */
}
