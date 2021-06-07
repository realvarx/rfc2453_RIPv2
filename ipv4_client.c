#include "eth.h"
#include "ipv4.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#define DEFAULT_PAYLOAD_LENGTH 1500

/* int main ( int argc, char * argv[] );
 *
 * DESCRIPCIÓN:
 *   Función principal del programa.
 *
 * PARÁMETROS:
 *   'argc': Número de parámetros pasados al programa por la línea de
 *           comandos, incluyendo el propio nombre del programa.
 *   'argv': Array con los parámetros pasado al programa por línea de
 *           comandos.
 *           El primer parámetro (argv[0]) es el nombre del programa.
 *
 * VALOR DEVUELTO:
 *   Código de salida del programa.
 */
int main ( int argc, char * argv[] )
{

  //printf("ENTRA AL MAIN");
  //puts("AAAAAAA");
  /* Mostrar mensaje de ayuda si el número de argumentos es incorrecto */
  char * myself = basename(argv[0]);
  if ((argc < 2) || (argc >3)) {
    printf("Uso: %s <iface> <IP>\n", myself);
    printf("       <iface>: Nombre de la interfaz Ethernet\n");
    printf("         <IP>: Dirección IP del servidor IPv4\n");
    exit(-1);
  }

  //printf("El fallo está antes del open y después de los input");
  //puts("El fallo está antes del open y después de los input");

  /* Procesar los argumentos de la línea de comandos */
  ipv4_addr_t server_addr;
  char *serverstr = argv[2];

  if ( ipv4_str_addr(serverstr, server_addr) != 0) {
    /*fprintf(stderr, "%s: Dirección IP del servidor incorrecta: '%s'\n",
            myself, argv[2]);*/
    exit(-1);
  }

  //printf("Antes de open");
  //puts("Antes de open");

  /* Abrir la interfaz Ethernet */
  ipv4_layer_t * ipv4_iface = ipv4_open("ipv4_config_client.txt",
                        "ipv4_route_table_client.txt");
  if (ipv4_iface == NULL) {
    //perror("")
    exit(-1);
  }

  //printf("Antes de dar valores al payload");
  //puts("Antes de dar valores al payload");

  unsigned char payload[IPv4_MTU];

  int i;
  for (i=0; i<IPv4_MTU; i++) {
    payload[i] = (unsigned char) i;
  }

  //printf("Antes del send");

  if(ipv4_send(ipv4_iface, server_addr, 17, payload, IPv4_MTU) == -1) {
    exit(-1);
  }

  ipv4_addr_t serverIp;
  unsigned char buffer[IPv4_MTU];

  //printf("Antes del recv");

  if(ipv4_recv(ipv4_iface, 17, buffer, serverIp, IPv4_MTU, 6000) == -1) {
    exit(-1);
  }

  char strServerIp[IPv4_STR_MAX_LENGTH];
  ipv4_addr_str(serverIp, strServerIp);


  printf("Packet has been recieved from : %s\n", strServerIp);

  //printf("Antes del printpkt");

  print_pkt(buffer, IPv4_MTU, 0);

  return 0;
}
