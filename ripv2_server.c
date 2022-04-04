#include <stdint.h>

#include "ripv2.h"
#include "ripv2_route_table.h"
#include "udp.h"
//#include "ipv4.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <timerms.h>
#include <string.h>
#include <libgen.h>
#include <arpa/inet.h>

#include <time.h>


void start_up_request();
void send_update();

int main(int argc, char *argv[])
{
    //char* host;
	//uint16_t port;
    //int length;


    switch (argc) {
	case 1:
		//port = argv[1];
		break;
	default:
		fprintf(stderr, "usage: %s <host> \n", argv[0]);
		exit(1);
    }

    ripv2_route_table_t *rip_table = ripv2_route_table_create();
    ripv2_route_table_read("ripv2_route_table_server.txt", rip_table);

    //ripv2_route_table_print (rip_table);

    udp_layer_t *layer = udp_open("ipv4_config_server.txt", "ipv4_route_table_server.txt", RIP_PORT);

    uint16_t client_port;
    ipv4_addr_t client_ip;
    
    unsigned char bufferRecv[RIP_MTU];
    ripv2_message_t *message = NULL;
    int firstTime = 1;
    long int timer = 0;

    time_t t;
    srand((unsigned) time(&t));
   
    timerms_t timer_update;
    long int time_left_update;
    int jitter = 15000 + rand()%30000;
    timerms_reset(&timer_update, jitter);
    printf("++++++ Jitter start value : %d seconds ++++++\n", jitter/1000);

    // Al arrancar, pedimos toda la tabla en multicast
    start_up_request(layer);

    ripv2_route_table_print (rip_table);

    while(1) {
        
        
        time_left_update = timerms_left(&timer_update);

        if(time_left_update == 0) {
            send_update(rip_table, layer);
            jitter = 15000 + rand()%30000;
            timerms_reset(&timer_update, jitter);
            printf("++++++ Jitter current value : %d seconds ++++++\n", jitter/1000);
            ripv2_route_table_print (rip_table);
        }


        firstTime = 1;
        //printf("PRINTEAMOS TABLA\n");
        //ripv2_route_table_print (rip_table);
        for (int i = 0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
            ripv2_route_t *tmp = ripv2_route_table_get(rip_table, i);
            if(tmp != NULL) {

                if(firstTime==1) {
                    timer = timerms_left(&tmp->timer);
                    firstTime = 0;
                }

                if(timer > timerms_left(&tmp->timer)) timer = timerms_left(&tmp->timer); 
            }
        }

        if(time_left_update < timer) timer = time_left_update;

        printf("timer: %ld\n", timer);

        int len_recv = udp_recv(layer, &client_port, bufferRecv, client_ip, RIP_MTU, timer);

        if(len_recv == -1) {
            perror("ERROR : ripv2_server error");
            exit(-1);
        } else if(len_recv == 0) {
            printf("TIMEOUT : ripv2_server\n");
            
            for (int i = 0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
            ripv2_route_t *tmp = ripv2_route_table_get(rip_table, i);
                if(tmp != NULL) {
                    if(timerms_left(&tmp->timer) == 0) {
                        if(tmp->metric == 16) {
                            ripv2_route_t *delete = ripv2_route_table_remove(rip_table, i);
                            ripv2_route_free(delete);
                            puts("Printeo por borrado\n");
                            //ripv2_route_table_print (rip_table);
                        } else {
                            printf("Ruta inválida, ponemos métrica a 16\n");
                            tmp->metric = 16;
                            timerms_reset(&tmp->timer, 120000);
                            puts("Printeo por garbage collector\n");
                            //ripv2_route_table_print (rip_table);
                        }
                    }
                }
            }
            
        } else {    // SI TODO VA BIEN

            message = (ripv2_message_t *) bufferRecv;
        
            if(message->command == 1) {     // ********* SI ES UN RESQUEST *********

                printf("HEMOS RECIBIDO UN REQUEST!");

                int entries = (len_recv - 4) / 20;
                int index_entries = 0;

                ripv2_message_t response;
                response.command = 2;
                response.version = 2;
                response.must_be_zero = 0x0000;

                if((entries == 1) && (message->entries[0].addr_family_id == 0x0000) 
                    && (ntohl(message->entries[0].metric) == 16)) {     // SI PIDE TODA LA TABLA

                    for(int i = 0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
                        ripv2_route_t *tmp_route_all = ripv2_route_table_get(rip_table, i);

                        if(tmp_route_all != NULL) {
                            response.entries[index_entries].addr_family_id = htons(2);
                            response.entries[index_entries].route_tag = 0x00;
                            memcpy(response.entries[index_entries].ip_addr, tmp_route_all->subnet_addr, IPv4_ADDR_SIZE);
                            memcpy(response.entries[index_entries].subnet_mask, tmp_route_all->subnet_mask, IPv4_ADDR_SIZE);
                            memcpy(response.entries[index_entries].next_hop, tmp_route_all->next_hop, IPv4_ADDR_SIZE); // 0.0.0.0 ??
                            response.entries[index_entries].metric = htonl(tmp_route_all->metric);

                            index_entries++;
                        }
                    }

                    int send_all = udp_send(layer, client_port, client_ip, (unsigned char *)&response, 4 + index_entries * 20);

                    if(send_all == -1) {
                        perror("ERROR : ripv2_server (response all entries)");
                        exit(-1);
                    }

                } else {    // SI NO NOS ESTÁ PIDIENDO TODA LA TABLA, HABRÁ QUE DARLE LO QUE NOS PIDA (SI LO TENEMOS)

                    for(int i = 0; i<entries; i++) {
                        ripv2_entry_t tmp_entry = message->entries[i];
                                                    //  TABLA - DIR SUBNET - MASK
                        int j = ripv2_route_table_find(rip_table, tmp_entry.ip_addr, tmp_entry.subnet_mask);

                        if((j != -2) && (j != -1)) {
                            ripv2_route_t *tmp_route_some = ripv2_route_table_get(rip_table, j);

                            response.entries[i].addr_family_id = htons(2);
                            response.entries[i].route_tag = 0x00;
                            memcpy(response.entries[i].ip_addr, tmp_route_some->subnet_addr, IPv4_ADDR_SIZE);
                            memcpy(response.entries[i].next_hop, tmp_route_some->next_hop, IPv4_ADDR_SIZE);
                            memcpy(response.entries[i].subnet_mask, tmp_route_some->subnet_mask, IPv4_ADDR_SIZE);
                            response.entries[i].metric = htonl(tmp_route_some->metric);

                        } else {
                            // LA TABLA ES NULL O NO HA ENCONTRADO LA RUTA ESPECIFICADA
                            // Se la devolvemos a métrica infinito, no sabemos llegar

                            response.entries[i].addr_family_id = htons(2);
                            response.entries[i].route_tag = 0x00;
                            memcpy(response.entries[i].ip_addr, tmp_entry.ip_addr, IPv4_ADDR_SIZE);
                            memcpy(response.entries[i].next_hop, tmp_entry.next_hop, IPv4_ADDR_SIZE);
                            memcpy(response.entries[i].subnet_mask, tmp_entry.subnet_mask, IPv4_ADDR_SIZE);
                            response.entries[i].metric = htonl(16);

                        }
                    }

                    // YA ESTÁ TODO CARGADO AL RESPONSE, LO MANDAMOS

                    // No es necesario calcular las entries de nuevo porque le vamos a mandar 
                    // tantas entries como nos haya pedido en este caso.

                    int send_some = udp_send(layer, client_port, client_ip, (unsigned char *)&response, 4 + entries * 20);
                    if(send_some == -1) {
                        perror("ERROR : ripv2_server (response requested entries)");
                        exit(-1);
                    }
                }
                //ripv2_route_table_print (rip_table);
            } else if(message->command == 2) {  // ********* SI ES UN RESPONSE *********

                int entries = (len_recv - 4) / 20;
                //int index_entries = 0;

                ripv2_entry_t tmp;
                for(int i = 0; i<entries; i++){
                    //ripv2_entry_t tmp = message->entries[i];
                    
                    memcpy(&tmp,&(message->entries[i]),20);

                    ipv4_addr_t nextHop;
                    if(memcmp(tmp.next_hop, IPv4_ZERO_ADDR, IPv4_ADDR_SIZE) == 0) {
                        memcpy(nextHop, client_ip, IPv4_ADDR_SIZE);
                    } else {
                        memcpy(nextHop, tmp.next_hop, IPv4_ADDR_SIZE);
                    }

                    int j = ripv2_route_table_find(rip_table, tmp.ip_addr, tmp.subnet_mask);

                    int updatedMetric = ntohl(tmp.metric) + 1;
                    if(updatedMetric > 16) updatedMetric = 16;

                    if(j == -2) {
                        perror("ERROR : ripv2_server (NULL table)");
                        exit(-1);

                    } else if(j == -1) {

                        if(updatedMetric < 16) {

                            ripv2_route_t *route = ripv2_route_create(tmp.ip_addr, 
                            tmp.subnet_mask, udp_getIfaceName(layer), nextHop, updatedMetric, 180000);

                            int err_add = ripv2_route_table_add(rip_table, route);
                            puts("Printeo por añadir nueva ruta\n");
                            //ripv2_route_table_print (rip_table);
                            if(err_add == -1){
                                perror("ERROR : ripv2_server (error adding new route)");
                            }
                        }

                    } else {
                        ripv2_route_t *route = ripv2_route_table_get(rip_table, j);

                        if(memcmp(route->next_hop, nextHop, IPv4_ADDR_SIZE) == 0) {

                            if(updatedMetric >= 16) {

                                if(route->metric < 16) {
                                    route->metric = 16;
                                    timerms_reset(&route->timer, 120000);
                                    puts("Printeo por garbage collector\n");
                                    //ripv2_route_table_print (rip_table);
                                }

                            } else {
                                route->metric = updatedMetric;
                                timerms_reset(&route->timer, 180000);
                                puts("Printeo por ruta inválida\n");
                                //ripv2_route_table_print (rip_table);
                            }
                        
                        } else if (updatedMetric < route->metric) {
                            memcpy(route->iface, udp_getIfaceName(layer), IFACE_NAME_MAX_LENGTH);
                            memcpy(route->next_hop, nextHop, IPv4_ADDR_SIZE);
                            route->metric = updatedMetric;

                            timerms_reset(&route->timer, 180000);
                            puts("Printeo por actualización a mejor métrica");
                            //ripv2_route_table_print (rip_table);
                        }
                        //ripv2_route_table_print (rip_table);
                    }
                    //ripv2_route_table_print (rip_table);
                }
                //ripv2_route_table_print(rip_table);
            } else {
                perror("ERROR : Invalid RIP packet command");
                exit(-1);
            }
        }
        ripv2_route_table_print (rip_table);
    }

    return 0;
}


void start_up_request(udp_layer_t *layer) {

    ipv4_addr_t ip_dst;

    ipv4_str_addr("224.0.0.9", ip_dst);

    //ipv4_str_addr(RIP_MULTICAST_ADDR, ip_dst);

    puts("ANTES DEL OPEN");
    printf("ANTES DEL OPEN");


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

    int length;

    length = udp_send(layer, RIP_PORT, ip_dst, (unsigned char *)&rip_request, 24);
    if(length == -1) {
        exit(-1);
    }

}

void send_update(ripv2_route_table_t *rip_table, udp_layer_t *layer) {

    // Envío periódico Response por multicast

    ipv4_addr_t ip_dst;

    ipv4_str_addr("224.0.0.9", ip_dst);

    int index_entries = 0;

    ripv2_message_t response;
    response.command = 2;
    response.version = 2;
    response.must_be_zero = 0x0000;


        for(int i = 0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
            ripv2_route_t *tmp_route_all = ripv2_route_table_get(rip_table, i);

            if(tmp_route_all != NULL) {
                response.entries[index_entries].addr_family_id = htons(2);
                response.entries[index_entries].route_tag = 0x00;
                memcpy(response.entries[index_entries].ip_addr, tmp_route_all->subnet_addr, IPv4_ADDR_SIZE);
                memcpy(response.entries[index_entries].subnet_mask, tmp_route_all->subnet_mask, IPv4_ADDR_SIZE);
                memcpy(response.entries[index_entries].next_hop, tmp_route_all->next_hop, IPv4_ADDR_SIZE); // 0.0.0.0 ??
                response.entries[index_entries].metric = htonl(tmp_route_all->metric);

                index_entries++;
            }
        }

        int send_all = udp_send(layer, RIP_PORT, ip_dst, (unsigned char *)&response, 4 + index_entries * 20);

        if(send_all == -1) {
            perror("ERROR : ripv2_server (response all entries)");
            exit(-1);
        }

}
