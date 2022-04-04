#ifndef _RIPV2SERVER_H
#define _RIPV2SERVER_H


void start_up_request(udp_layer_t * layer);
void send_update(ripv2_route_table_t *rip_table, udp_layer_t *layer);

#endif