## RIPv2 Daemon

### Librawnet library is required for the correct functioning of the program.

/COMPILE CLIENT/

*rawnetcc ripv2_client eth.c arp.c ipv4.c ipv4_config.c ipv4_route_table.c ripv2_route_table.c udp.c ripv2_client.c*

/RUN CLIENT/

*./ripv2_client*


/COMPILE SERVER/

*rawnetcc ripv2_server eth.c arp.c ipv4.c ipv4_config.c ipv4_route_table.c ripv2_route_table.c udp.c ripv2_server.c*

/RUN SERVER/

*./ripv2_server [host]*
