#include "eth.h"
#include "ipv4.h"
#include "arp.c"
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>



int main(int argc, char *argv[]) {
    
    
  char * myself = basename(argv[0]);
  if ((argc < 3) || (argc > 3)) {
    printf("Uso: %s <iface> <ip>\n", myself);
    printf("       <iface>: Nombre de la interfaz Ethernet\n");
    printf("         <ip>: Dirección IP del servidor\n");
    exit(-1);
  }

  eth_iface_t *currentIface = eth_open(argv[1]);
  ipv4_addr_t currentIP;
  mac_addr_t resultMac;

  if( currentIface == NULL)  {
    perror("Error : Invalid interface");
    exit(0);
  }
  
  if ( ipv4_str_addr(argv[2], currentIP) == -1 ) {
    perror("Error : Invalid IP");
    exit(0);
  }
  
  if ( arp_resolve( currentIface, currentIP, resultMac, currentIP) == -1 ) {
    perror("Error : Couldn't resolve ARP.");
    exit(0);
  }
  char *macStr;
  mac_addr_str(resultMac, macStr);
  
  printf("%s -> %s", argv[2], macStr);

  return (EXIT_SUCCESS);
}
