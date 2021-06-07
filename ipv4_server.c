#include "eth.h"
#include "ipv4.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#define DEFAULT_PAYLOAD_LENGTH 1500

int main(int argc, char *argv[])
{
    ipv4_layer_t *layer = ipv4_open("ipv4_config_server.txt",
                        "ipv4_route_table_server.txt");

    unsigned char buffer[IPv4_MTU];
    ipv4_addr_t receivedIp;

    while(1) {
        if (ipv4_recv(layer, 17, buffer, receivedIp, IPv4_MTU, -1) == -1) {
            exit(-1);
        }

        char strReceivedIp[IPv4_STR_MAX_LENGTH];

        ipv4_addr_str(receivedIp, strReceivedIp);
        printf("Information recieved from %s\n", strReceivedIp);
        if(ipv4_send(layer, receivedIp, 17, buffer, IPv4_MTU) == -1) {
            exit(-1);
            puts("Information has been sent back to client");
        }
    }
    return 0;
}
