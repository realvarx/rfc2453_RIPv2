#include <rawnet.h>
#include <timerms.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <arpa/inet.h>
#include "eth.h"
#include "ipv4.h"
#include "arp.h"

#define MAX_BUFF_LEN 1500
#define TIMEOUT 2000

mac_addr_t MAC_ZERO_ADDR = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//mac_addr_t THIS_MAC_ADDRESS = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

//int arp_resolve ( eth_iface_t *iface, ipv4_addr_t dest, mac_addr_t mac);

//void ipv4_addr_str(ipv4_addr_t addr, char str[]);
//int ipv4_str_addr(char *str, ipv4_addr_t addr);

struct arp_frame {
    uint16_t hdr;   //Hardware type
    uint16_t pro;   //Protocol type
    uint8_t hln;    //Hardware address length
    uint8_t pln;    //Protocol address length
    uint16_t op;    //Opcode (arp request[1] or reply[2])
    mac_addr_t senderMac; //Sender MAC Address
    ipv4_addr_t senderIp; //Sender IP Address
    mac_addr_t targetMac; //Target MAC Address
    ipv4_addr_t targetIp; // Target IP Address
};

typedef struct arp_frame arp_frame_t;

/* int arp_resolve ( eth_iface_t *iface, ipv4_addr_t dest, mac_addr_t mac);
 *
 * DESCRIPCIÓN:
 *   Esta función permite obtener la dirección MAC del sistema con el cual
 *   se desea obtener comunicación a partir de su dirección IPV4 mediante el
 *   protocolo ARP.
 *
 * PARÁMETROS:
 *    'iface': Manejador de la interfaz Ethernet por la que se desea recibir
 *             un paquete.
 *             La interfaz debe haber sido inicializada con 'eth_open()'
 *             previamente.
 *
 *     'dest': Dirección IPV4 de la cual se desea obtener la dirección MAC
 *             utilizando el protocolo ARP.
 *
 *      'mac': Dirección MAC correspondiente a la IPV4 introducida obtenida
 *             a través de ARP.
 *
 * VALOR DEVUELTO:
 *   Si el paquete ARP es recibido correctamente, retorna 0.
 *
 * ERRORES:
 *   La función devuelve '-1' si se ha producido algún error.
 */

int arp_resolve ( eth_iface_t *iface, ipv4_addr_t dest,
  mac_addr_t mac, ipv4_addr_t senderIp) {

    //ipv4_str_addr();
    //mac_addr_t result;
    unsigned char bufferReceived[1500];
    mac_addr_t myaddr;
    eth_getaddr(iface, myaddr);
    //Lo primero, generamos el frame

    arp_frame_t frame;
    frame.hdr = htons(1);  //Network link protocol type (Ethernet is 1)
    frame.pro = htons(0x0800); //IANA IP TYPE CODE
    frame.hln = 6;
    frame.pln = 4;
    frame.op = htons(1);
    //frame.senderMac; // FIXME: mi dir MAC
    memcpy(frame.senderMac, myaddr, sizeof(mac_addr_t));
    memcpy(frame.senderIp, senderIp, sizeof(ipv4_addr_t));
    //frame.targetMac; // FIXME: 00:00:00:00:00:00
    memcpy(frame.targetMac, MAC_ZERO_ADDR, sizeof(mac_addr_t));
    memcpy(frame.targetIp, dest, sizeof(ipv4_addr_t));
    //Lo enviamos

    eth_send(iface, MAC_BCAST_ADDR, 0x0806, (unsigned char *)&frame, sizeof(frame));

    //Por último, esperamos a recibir respuesta. Si no hay en 2 segundos, return.

    int timeout = 2000;
    timerms_t timer;
    timerms_reset(&timer, timeout);

    arp_frame_t *recieved;

    int is_ip;
    int is_opreply;
    int n;
    

    do {

        // Retransmisión ARP //

        int retransmission = 1;

        do{

            long int time_left = timerms_left(&timer);

            n = eth_recv(iface, (unsigned char *) mac, 0x0806, 
            bufferReceived, MAX_BUFF_LEN, time_left);

            if(n == -1) {
                perror("ERROR ARP ");
                return -1;
            }

            if(n == 0) {
                perror ("TIMEOUT O VACÍO ARP");
                
                if(retransmission == 1) {
                    retransmission = 0;
                } else {
                    return 0;
                }
                
            }

        }while((n == 0) || (n == -1));

        // Retransmisión ARP //

        recieved = (arp_frame_t*)bufferReceived;
        is_ip = (memcmp(dest, recieved->senderIp, sizeof(ipv4_addr_t))==0);
        uint16_t opcode_received = ntohs(recieved->op);
        is_opreply = (opcode_received == 2);

        printf("VALOR DE IS_IP : %d\n", is_ip);
        
    }while(!(is_ip && is_opreply));

    return n;
}
