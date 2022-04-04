#include "ipv4.h"
#include "ipv4_route_table.h"
#include "ipv4_config.h"

#include "eth.h"
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <timerms.h>
#include <string.h>
#include <libgen.h>
#include <arpa/inet.h>

/* Dirección IPv4 a cero: "0.0.0.0" */
ipv4_addr_t IPv4_ZERO_ADDR = { 0, 0, 0, 0 };
ipv4_addr_t RIP_MULTICAST_ADDR = {224, 0, 0, 9};

/*      LA MODIFICACIÓN PARA MULTICAST HA SIDO AÑADIDA       */

#define IPv4_HEADER_SIZE 20
#define IPv4_TYPE 0x0800

struct ipv4_layer {
  eth_iface_t *iface; // iface=eth_open("eth1");
  ipv4_addr_t addr;   // 192.168.1.1
  ipv4_addr_t netmask;  // 255.255.255.0
  ipv4_route_table_t *routing_table;

};

char *ipv4_getIfaceName(ipv4_layer_t *layer){
  return eth_getname(layer->iface);
}

void ipv4_get_addr (ipv4_layer_t *layer,  ipv4_addr_t addr )
{
  if(layer != NULL){
    memcpy(addr, layer->addr, MAC_ADDR_SIZE);
  }
}

/*int retrieveSizeOfLayer() {
  return sizeof(struct ipv4_layer);
}*/

/*int ipv4_send (ipv4_layer_t * layer, ipv4_addr_t dst, uint8_t protocol,
  unsigned char * payload, int payload_len) {}*/

/* MTU for IPv4 is 64 KiB (kibibit; 1KiB = 128 bytes) */
/* 64 KiB are 51200 bits */

//checksum uint16_t




ipv4_layer_t *ipv4_open(char * file_conf, char * file_conf_route) {

  /* 1. Crear layer -> routing_table */

  ipv4_layer_t * layer = (ipv4_layer_t*)malloc(sizeof(ipv4_layer_t));

  /* 2. Leer direcciones y subred de file_conf */

  char tmpIfname[IFACE_NAME_MAX_LENGTH];
  ipv4_addr_t readAddr;
  ipv4_addr_t readNetmask;

  // ipv4_config_client.txt

  if( ipv4_config_read(file_conf, tmpIfname,
      readAddr, readNetmask) == -1) {

    perror("Error reading the file.");
    return NULL;
  }

  /* 3. Leer tabla de reenvío IP de file_conf_route */

  ipv4_route_table_t * tmpTable = ipv4_route_table_create();

  puts("Después de crear la tabla de rutas");

  // ipv4_route_table_client.txt

  if( ipv4_route_table_read(file_conf_route,
      tmpTable) == -1) return NULL;

   layer->routing_table = tmpTable;
   memcpy(&layer->addr, readAddr, IPv4_ADDR_SIZE);
   memcpy(&layer->netmask, readNetmask, IPv4_ADDR_SIZE);

  /* 4. Inicializar capa Ethernet con eth_open() */

  layer->iface = eth_open(tmpIfname);

  char strip[IPv4_STR_MAX_LENGTH];
  ipv4_addr_str(readAddr, strip);
  printf("DEBUG IPV4 OPEN : %s\n", strip);

  return layer;
}

int ipv4_close(ipv4_layer_t * layer) {

  int err = -1;

  /* 1. Liberar tabla de rutas (layer->routing_table) */

  ipv4_route_table_free(layer->routing_table);

  /* 2. Cerrar capa Ethernet con eth_close() */

  err = eth_close(layer->iface);

  free(layer);

  return err;

}

int ipv4_send (ipv4_layer_t * layer, ipv4_addr_t dst, uint8_t protocol,
  unsigned char * payload, int payload_len) {


    int multicast = 0;
    mac_addr_t mac_multicast;



    multicast = ((dst[0] & 0xF0) == 0xE0);  // ES MULTICAST

    if(multicast) {

      // 01:00:5E

      mac_multicast[0] = 0x01;
      mac_multicast[1] = 0x00;
      mac_multicast[2] = 0x5E;

      // 01:00:5E + 23 ultimos bits ipv4

      mac_multicast[3] = (dst[1] & 0x7F); // 01111111
      mac_multicast[4] = (dst[2] & 0xFF); // 11111111
      mac_multicast[5] = (dst[3] & 0xFF); // 11111111

    }

    int err = -1;

    // PROTOCOL IANA : 0x0800 for IPv4

    if (layer == NULL) {
      fprintf(stderr, "ipv4_send(): ERROR: layer == NULL\n");
      return -1;
    }

    ipv4_frame_t ipv4_frame;

    ipv4_frame.version_hlen = 0x45;
    ipv4_frame.type_of_service = 0x00;
    ipv4_frame.protocol = protocol;
    ipv4_frame.total_length = htons(IPv4_HEADER_SIZE + payload_len);
    ipv4_frame.identification = htons(0);
    ipv4_frame.flags_offset = htons(0x4000);
    ipv4_frame.ttl = 64;
    if(multicast) ipv4_frame.ttl = 1;
    ipv4_frame.checksum = 0x0000;

    memcpy(ipv4_frame.src_addr, layer->addr, IPv4_ADDR_SIZE);
    memcpy(ipv4_frame.dest_addr, dst, IPv4_ADDR_SIZE);
    memcpy(ipv4_frame.payload, payload, payload_len);

    ipv4_route_t *bestroute = ipv4_route_table_lookup(layer->routing_table, dst);

    if (bestroute == NULL) {
      perror("Unreachable host.");
      exit(-1);
    }

    mac_addr_t buffMac;

    if (memcmp(bestroute->gateway_addr, IPv4_ZERO_ADDR, IPv4_ADDR_SIZE) != 0) {
      printf("Not in the same subnet\n");
      int err_nozero  = arp_resolve(layer->iface, bestroute->gateway_addr, buffMac, layer->addr);
      if(err_nozero  == -1) {
        fprintf(stderr, "ipv4_send(): ERROR: Couldn't resolve MAC\n");
        return -1;
      }
    } else {
      int err_zero = arp_resolve(layer->iface, dst, buffMac, layer->addr);
      if(err_zero  == -1) {
        fprintf(stderr, "ipv4_send(): ERROR: Couldn't resolve MAC\n");
        return -1;
      }
    }

    
    
    /*if ( arp_resolve(layer->iface, dst, buffMac, layer->addr) == -1 ) {
      fprintf(stderr, "ipv4_send(): ERROR: Couldn't resolve MAC\n");
      return -1;
    }*/

    ipv4_frame.checksum = htons(ipv4_checksum((unsigned char*)&ipv4_frame,
                          IPv4_HEADER_SIZE));

    if(multicast) memcpy(buffMac, mac_multicast, MAC_ADDR_SIZE);

    err = eth_send(layer->iface, buffMac, 0x0800,
          (unsigned char *)&ipv4_frame, IPv4_HEADER_SIZE + payload_len);
                                        //sizeof(ipv4_frame)

    if ( err == -1 ) {
      fprintf(stderr, "ipv4_send(): ERROR: Couldn't send IPv4 frame\n");
      return -1;
    }

    return err;
}

int ipv4_recv(ipv4_layer_t * layer, uint8_t protocol, unsigned char buffer[],
              ipv4_addr_t sender, int buf_len, long int timeout) {

    if (layer == NULL) {
      fprintf(stderr, "ipv4_recv(): ERROR: layer == NULL\n");
      return -1;
    }

    timerms_t timer;
    timerms_reset(&timer, timeout);

    mac_addr_t buffMac;
    unsigned char payload[buf_len + IPv4_HEADER_SIZE];
    int is_my_ipv4;
    int is_target_type;
    int frame_len;
    int multicast;

    //arp_resolve(layer->iface, sender, buffMac, layer->addr);
    ipv4_frame_t *ip_header = NULL;

    do {

      long int time_left = timerms_left(&timer);

      frame_len = eth_recv(layer->iface, buffMac, 0x0800,
        payload, buf_len + IPv4_HEADER_SIZE, time_left);

      if (frame_len < 0) {
        fprintf(stderr, "ipv4_recv(): ERROR en eth_recv()\n");
        return -1;
      } else if (frame_len == 0) {
        printf("ipv4_recv() : Timeout IPv4\n");
        return 0;
      } else if (frame_len < IPv4_HEADER_SIZE) {
        fprintf(stderr, "ipv4_recv(): Trama de tamaño invalido: %d bytes\n",
                frame_len);
        continue;
      }


      ip_header = (ipv4_frame_t *) payload;

      //char strReceivedIp[IPv4_STR_MAX_LENGTH];

      //ipv4_addr_str(ip_header->dest_addr, strReceivedIp);
      //printf("DEBUG IPV4 DSTADDR : %s\n", strReceivedIp);

      is_my_ipv4 = (memcmp(ip_header->dest_addr,
                          layer->addr, sizeof(ipv4_addr_t)) == 0);
      is_target_type = (ip_header->protocol == protocol);

      //                                       240      224

      multicast = ((ip_header->dest_addr[0] & 0xF0) == 0xE0);

    } while(!((is_my_ipv4 || multicast) && is_target_type));

    printf("RECIBO IP\n");

    memcpy(sender, ip_header->src_addr, IPv4_ADDR_SIZE);
    memcpy(buffer, ip_header->payload, ntohs(ip_header->total_length) - 20);

    /*if(ipv4_checksum((unsigned char*)&ip_header, ntohs(ip_header->total_length)) != ntohs(ip_header->checksum)) {
      printf("ipv4_recv : bad checksum");
    }*/

    return ntohs(ip_header->total_length) - 20;
}

/* void ipv4_addr_str ( ipv4_addr_t addr, char* str );
 *
 * DESCRIPCIÓN:
 *   Esta función genera una cadena de texto que representa la dirección IPv4
 *   indicada.
 *
 * PARÁMETROS:
 *   'addr': La dirección IP que se quiere representar textualente.
 *    'str': Memoria donde se desea almacenar la cadena de texto generada.
 *           Deben reservarse al menos 'IPv4_STR_MAX_LENGTH' bytes.
 */
void ipv4_addr_str ( ipv4_addr_t addr, char* str )
{
  if (str != NULL) {
    sprintf(str, "%d.%d.%d.%d",
            addr[0], addr[1], addr[2], addr[3]);
  }
}


/* int ipv4_str_addr ( char* str, ipv4_addr_t addr );
 *
 * DESCRIPCIÓN:
 *   Esta función analiza una cadena de texto en busca de una dirección IPv4.
 *
 * PARÁMETROS:
 *    'str': La cadena de texto que se desea procesar.
 *   'addr': Memoria donde se almacena la dirección IPv4 encontrada.
 *
 * VALOR DEVUELTO:
 *   Se devuelve 0 si la cadena de texto representaba una dirección IPv4.
 *
 * ERRORES:
 *   La función devuelve -1 si la cadena de texto no representaba una
 *   dirección IPv4.
 */
int ipv4_str_addr ( char* str, ipv4_addr_t addr )
{
  int err = -1;

  if (str != NULL) {
    unsigned int addr_int[IPv4_ADDR_SIZE];
    int len = sscanf(str, "%d.%d.%d.%d",
                     &addr_int[0], &addr_int[1],
                     &addr_int[2], &addr_int[3]);

    if (len == IPv4_ADDR_SIZE) {
      int i;
      for (i=0; i<IPv4_ADDR_SIZE; i++) {
        addr[i] = (unsigned char) addr_int[i];
      }

      err = 0;
    }
  }

  return err;
}


/*
 * uint16_t ipv4_checksum ( unsigned char * data, int len )
 *
 * DESCRIPCIÓN:
 *   Esta función calcula el checksum IP de los datos especificados.
 *
 * PARÁMETROS:
 *   'data': Puntero a los datos sobre los que se calcula el checksum.
 *    'len': Longitud en bytes de los datos.
 *
 * VALOR DEVUELTO:
 *   El valor del checksum calculado.
 */
uint16_t ipv4_checksum ( unsigned char * data, int len )
{
  int i;
  uint16_t word16;
  unsigned int sum = 0;

  /* Make 16 bit words out of every two adjacent 8 bit words in the packet
   * and add them up */
  for (i=0; i<len; i=i+2) {
    word16 = ((data[i] << 8) & 0xFF00) + (data[i+1] & 0x00FF);
    sum = sum + (unsigned int) word16;
  }

  /* Take only 16 bits out of the 32 bit sum and add up the carries */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  /* One's complement the result */
  sum = ~sum;

  return (uint16_t) sum;
}
