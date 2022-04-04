#include "ipv4.h"
//#include "ipv4.c"
//#include "eth.c"
#include "arp.h"
#include "eth.h"
#include "udp.h"
//#include "arp.c"
#include "ipv4_config.h"
#include "ipv4_route_table.h"

// #include <sys/socket.h>
// #include <netinet/in.h>

#include <arpa/inet.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <timerms.h>
#include <unistd.h>

/* udp_open() */
/* udp_close() */
/* udp_send() */
/* udp_recv() */

// 65535 is max port (uint16_t)

// Min port would be 1025 (>1024)

struct udp_layer
{
    ipv4_layer_t *ipv4_layer;
    uint16_t port;
    /* Incompleto, ¡solo puertos! (hacer de socket) */
}; /* Y si no, variables uint16_t para los puertos */

char *udp_getIfaceName(udp_layer_t *layer)
{
    return ipv4_getIfaceName(layer->ipv4_layer);
}

typedef struct udp_frame
{
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum; // A CEROS
    unsigned char payload[UDP_MTU];
} udp_frame_t;

typedef struct udp_with_pseudoheader
{
    ipv4_addr_t src_ip;
    ipv4_addr_t dest_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;

    udp_frame_t frame;
} udp_with_pseudoheader_t;

udp_layer_t *udp_open(char *file_conf, char *file_conf_route, uint16_t port)
{
    uint16_t random_port = 0;

    // PUERTO ALEATORIO UDP

    if (port == 0)
    {
        time_t t;
        srand((unsigned)time(&t));

        // 65535 - 1025 = 64510

        random_port = 1025000 + rand() % 64510000;

        printf("Puerto UDP actual para udp_open() : %d\n", random_port);
    }
    else
    {
        random_port = port;
    }

    // PUERTO ALEATORIO UDP

    udp_layer_t *udp_layer = (udp_layer_t *)malloc(sizeof(udp_layer_t));
    ipv4_layer_t *ipv4_layer = NULL; // = (ipv4_layer_t *)malloc(retrieveSizeOfLayer());

    // HACER GESTIÓN DE ERRORES

    /* ipv4_open("ipv4_config_client.txt", "ipv4_route_table_client.txt"); */

    /* udp_frame_t udp_frame;

    udp_frame->src_port = src_port;
    udp_frame->dest_port = dest_port; */

    /* ipv4_layer_t *ipv4_open(char * file_conf, char * file_conf_route) */

    puts("ANTES DEL IPV4 OPEN");

    ipv4_layer = ipv4_open(file_conf, file_conf_route);
    puts("ANTES DE ASIGNAR EL IPV4LAYER");
    udp_layer->ipv4_layer = ipv4_layer;
    // memcpy(&udp_layer->ipv4_layer, &ipv4_layer, sizeof(ipv4_layer));

    puts("DESPUÉS DEL IPV4 OPEN");

    // Este memcpy está modificado para random_port

    memcpy(&udp_layer->port, &random_port, sizeof(uint16_t));
    // udp_layer->src_port = src_port;
    // udp_layer->src_port = PORT;
    // udp_layer->dest_port = dest_port;
    // udp_layer->frame = udp_frame;

    return udp_layer;
}

int udp_close(udp_layer_t *layer)
{
    int err = -1;

    err = ipv4_close(layer->ipv4_layer);

    free(layer);

    return err;
}

int udp_send(udp_layer_t *layer, uint16_t dest_port, ipv4_addr_t dst, unsigned char *payload, int payload_len)
{
    // EL CÓDIGO DE UDP ES 17

    /*
  typedef struct udp_frame {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum; // A CEROS
    unsigned char *payload;
  } udp_frame_t;
    */
    udp_frame_t udpFrame;

    udpFrame.dest_port = htons(dest_port);
    udpFrame.src_port = htons(layer->port);
    memcpy(udpFrame.payload, payload, payload_len);
    udpFrame.checksum = 0x0000;
    udpFrame.length = htons(payload_len + UDP_HEADER_SIZE);

    /*udp_with_pseudoheader_t checksum;
    ipv4_addr_t tmpAddr;

    ipv4_get_addr(layer->ipv4_layer,  tmpAddr);

    memcpy(checksum.src_ip, tmpAddr, IPv4_ADDR_SIZE);
    memcpy(checksum.dest_ip, dst, IPv4_ADDR_SIZE);
    checksum.zero = 0x00;
    checksum.protocol = 17;
    checksum.length = udpFrame.length;
    memcpy(&checksum.frame, &udpFrame, UDP_HEADER_SIZE + payload_len);

    udpFrame.checksum = htons(ipv4_checksum((unsigned char*)&checksum,
    udpFrame.length + 12));
    */
    // memcpy(&udp_frame->src_port, &layer->port, sizeof(uint16_t));
    // memcpy(&udp_frame->dest_port, &dest_port, sizeof(uint16_t));
    // memcpy(udp_frame->length, payload_len + UDP_HEADER_SIZE,
    // sizeof(uint16_t)); memcpy(&udp_frame->checksum, 0, sizeof(uint16_t));

    if (ipv4_send(layer->ipv4_layer, dst, 17, (unsigned char *)&udpFrame, payload_len + UDP_HEADER_SIZE) == -1)
    {
        fprintf(stderr, "udp_send(): ERROR: Couldn't send UDP frame\n");
        return -1;
    }
    return 0;
}

int udp_recv(udp_layer_t *layer, uint16_t *src_port, unsigned char buffer[], ipv4_addr_t sender, int buf_len,
             long int timeout)
{
    if (layer == NULL)
    {
        fprintf(stderr, "udp_recv(): ERROR: layer == NULL\n");
        return -1;
    }

    timerms_t timer;
    timerms_reset(&timer, timeout);

    unsigned char payload[buf_len + UDP_HEADER_SIZE];
    ipv4_addr_t senderIp;
    int is_my_port;
    // int is_target_type;
    int frame_len;

    udp_frame_t *udp_frame = NULL;

    /* int ipv4_recv(ipv4_layer_t * layer, uint8_t protocol, unsigned char
       buffer[], ipv4_addr_t sender, int buf_len, long int timeout) */

    do
    {
        long int time_left = timerms_left(&timer);

        frame_len = ipv4_recv(layer->ipv4_layer, 17, payload, senderIp, buf_len + UDP_HEADER_SIZE, time_left);

        if (frame_len < 0)
        {
            fprintf(stderr, "udp_recv(): ERROR en ipv4_recv()\n");
            return -1;
        }
        else if (frame_len == 0)
        {
            /* Timeout! */
            puts("TIMEOUT");
            return 0;
        }
        else if (frame_len < UDP_HEADER_SIZE)
        {
            fprintf(stderr, "udp_recv(): Trama de tamaño invalido: %d bytes\n", frame_len);
            continue;
        }

        udp_frame = (udp_frame_t *)payload;

        /* Hacer casting a cabecera IP del payload recibido */
        /* Hacer htohs */
        /* Protocolo (tipo) */

        is_my_port = (ntohs(udp_frame->dest_port) == layer->port);
        // is_target_type = (ntohs(udp_header->protocol) == protocol);

    } while (!is_my_port);

    uint16_t recvPort = ntohs(udp_frame->src_port);

    // memcpy(src_port, &udp_frame->src_port, sizeof(uint16_t));
    memcpy(src_port, &recvPort, sizeof(uint16_t));
    memcpy(sender, senderIp, IPv4_ADDR_SIZE);
    memcpy(buffer, udp_frame->payload,
           ntohs(udp_frame->length) - 8); // SIN HEADERS

    char strip[IPv4_STR_MAX_LENGTH];
    ipv4_addr_str(senderIp, strip);
    printf("DEBUG UDP RECV IP : %s\n", strip);

    /*udp_with_pseudoheader_t checksum;

    ipv4_addr_t tmpAddr;

    //ipv4_str_addr(get_layer_addr(layer->ipv4_layer), tmpAddr);
    ipv4_get_addr(layer->ipv4_layer,  tmpAddr);


    memcpy(checksum.src_ip, senderIp, IPv4_ADDR_SIZE);
    memcpy(checksum.dest_ip, tmpAddr, IPv4_ADDR_SIZE);
    checksum.zero = 0x00;
    checksum.protocol = 17;
    memcpy(&checksum.length, &udp_frame->length, sizeof(uint16_t));
    //memcpy(checksum.frame, &udp_frame, sizeof(udp_frame_t));
    checksum.frame = *udp_frame;

    uint16_t check_result = ipv4_checksum((unsigned char*)&checksum,
    udp_frame->length + 12);


    if(memcmp(&udp_frame->checksum, &check_result, sizeof(uint16_t)) == 0) {
      printf("UDP : Checksum correct");
    } else {
      printf("UDP : Incorrect checksum");
    }
    */

    return ntohs(udp_frame->length) - 8;
}
