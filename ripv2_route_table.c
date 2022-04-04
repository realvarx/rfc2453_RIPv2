#include "ripv2_route_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ipv4_route_table.h"



ripv2_route_t * ripv2_route_create(ipv4_addr_t subnet, ipv4_addr_t mask, char *iface, 
                                    ipv4_addr_t nextHop, int metric, long int timeout) {

  ripv2_route_t * route = (ripv2_route_t *) malloc(sizeof(struct ripv2_route));

  if((route != NULL) && (subnet != NULL) && (mask != NULL) && (iface != NULL) && 
    (metric != 0) && (timeout != 0)) {

    memcpy(route->subnet_addr, subnet, IPv4_ADDR_SIZE);
    memcpy(route->subnet_mask, mask, IPv4_ADDR_SIZE);
    strncpy(route->iface, iface, IFACE_NAME_MAX_LENGTH);
    memcpy(route->next_hop, nextHop, IPv4_ADDR_SIZE);
    //memcpy(route->metric, metric, sizeof(int));
    route->metric = metric;
    timerms_reset(&route->timer, timeout);
  }
  return route;
}



int ripv2_route_lookup(ripv2_route_t *route, ipv4_addr_t addr)
{
  int prefix_length = -1;

  int arrayResult[3];

  ipv4_addr_t mask;
  ipv4_addr_t subnet;

  memcpy(mask, route->subnet_mask, sizeof(ipv4_addr_t));
  memcpy(subnet, route->subnet_addr, sizeof(ipv4_addr_t));

  for(int i = 0; i<4; i++) {
    arrayResult[i] = addr[i] & mask[i];
    if(arrayResult[i] != subnet[i]) return prefix_length;
  }

  //Si ha llegado aquí es que coinciden, ahora hay que buscar la longitud del prefijo

  prefix_length = 0;

  for(int i = 0; i<4; i++) {
    switch (arrayResult[i]) {
      case 255: prefix_length = prefix_length + 8;
      case 254: prefix_length = prefix_length + 7;
      case 252: prefix_length = prefix_length + 6;
      case 248: prefix_length = prefix_length + 5;
      case 240: prefix_length = prefix_length + 4;
      case 224: prefix_length = prefix_length + 3;
      case 192: prefix_length = prefix_length + 2;
      case 128: prefix_length = prefix_length + 1;

      default : prefix_length = prefix_length + 0;
    }
  }

  return prefix_length;
}



void ripv2_route_print(ripv2_route_t *route)
{
  if(route != NULL) {
    char subnet_str[IPv4_STR_MAX_LENGTH];
    ipv4_addr_str(route->subnet_addr, subnet_str);
    char mask_str[IPv4_STR_MAX_LENGTH];
    ipv4_addr_str(route->subnet_mask, mask_str);
    char* iface_str = route->iface;
    char nextHop_str[IPv4_STR_MAX_LENGTH];
    ipv4_addr_str(route->next_hop, nextHop_str);
    int metric = route->metric;
    long int timer = timerms_left(&route->timer);

    printf("%s/%s via %s dev %s [metric : %d] [timer : %ld]\n", 
    subnet_str, mask_str, nextHop_str, iface_str, metric, timer);
  }
}



void ripv2_route_free(ripv2_route_t *route) 
{
    if(route != NULL) {
        free(route);
    }
}



ripv2_route_t* ripv2_route_read (char* filename, int linenum, char * line)
{
  ripv2_route_t* route = NULL;

  char subnet_str[256];
  char mask_str[256];
  char iface_name[256];
  char nh_str[256];
  char metric_str[256];
  char timer_str[256];

  /* Parse line: Format "<subnet> <mask> <iface> <nextHop> <metric> <timer>\n" */
  int params = sscanf(line, "%s %s %s %s %s %s\n",
	       subnet_str, mask_str, iface_name, nh_str, metric_str, timer_str);
  if (params != 6) {
    fprintf(stderr, "%s:%d: Invalid RIPv2 Route format: '%s' (%d params)\n",
	    filename, linenum, line, params);
    fprintf(stderr,
	    "%s:%d: Format must be: <subnet> <mask> <iface> <nextHop> <metric> <timer>\n",
	    filename, linenum);
    return NULL;
  }

  /* Parse IPv4 route subnet address */
  ipv4_addr_t subnet;
  int err = ipv4_str_addr(subnet_str, subnet);
  if (err == -1) {
    fprintf(stderr, "%s:%d: Invalid <subnet> value: '%s'\n",
	    filename, linenum, subnet_str);
    return NULL;
  }

  /* Parse IPv4 route subnet mask */
  ipv4_addr_t mask;
  err = ipv4_str_addr(mask_str, mask);
  if (err == -1) {
    fprintf(stderr, "%s:%d: Invalid <mask> value: '%s'\n",
	    filename, linenum, mask_str);
    return NULL;
  }

  /* Parse IPv4 route gateway */
  ipv4_addr_t nextHop;
  err = ipv4_str_addr(nh_str, nextHop);
  if (err == -1) {
    fprintf(stderr, "%s:%d: Invalid <gw> value: '%s'\n",
	    filename, linenum, nh_str);
    return NULL;
  }

  int metric = atoi(metric_str);

  int timeout = atoi(timer_str);

  /* Create new route with parsed parameters */
  route = ripv2_route_create(subnet, mask, iface_name, nextHop, metric, timeout);
  if (route == NULL) {
    fprintf(stderr, "%s:%d: Error creating the new route\n",
	    filename, linenum);
  }

  return route;
}



int ripv2_route_output (ripv2_route_t * route, int header, FILE * out)
{
  int err;

  if (header == 0) {
    err = fprintf(out, "# SubnetAddr  \tSubnetMask    \tIface  \tNextHop    \tMetric   \tTimeout\n");
    if (err < 0) {
      return -1;
    }
  }

  char subnet_str[IPv4_STR_MAX_LENGTH];
  char mask_str[IPv4_STR_MAX_LENGTH];
  char* ifname = NULL;
  char nh_str[IPv4_STR_MAX_LENGTH];
  int metric;
  long int timer;

  if (route != NULL) {
      ipv4_addr_str(route->subnet_addr, subnet_str);
      ipv4_addr_str(route->subnet_mask, mask_str);
      ifname = route->iface;
      ipv4_addr_str(route->next_hop, nh_str);
      metric = route->metric;
      timer = timerms_left(&(route->timer));

      err = fprintf(out, "%-15s\t%-15s\t%s\t%-15s\t%d\t%ld\n",
		    subnet_str, mask_str, ifname, nh_str, metric, timer);
      if (err < 0) {
        return -1;
      }
  }

  return 0;
}



ripv2_route_table_t * ripv2_route_table_create()
{
  ripv2_route_table_t * table;

  table = (ripv2_route_table_t *) malloc(sizeof(struct ripv2_route_table));
  if (table != NULL) {
    int i;
    for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
      table->routes[i] = NULL;
    }
  }

  return table;
}



int ripv2_route_table_add (ripv2_route_table_t * table, ripv2_route_t * route)
{
  int route_index = -1;

  if (table != NULL) {
    /* Find an empty place in the route table */
    int i;
    for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
      if (table->routes[i] == NULL) {
        table->routes[i] = route;
        route_index = i;
        break;
      }
    }
  }

  return route_index;
}



ripv2_route_t *ripv2_route_table_remove(ripv2_route_table_t *table, int index)
{
  ripv2_route_t * removed_route = NULL;

  if ((table != NULL) && (index >= 0) && (index < RIPv2_ROUTE_TABLE_SIZE)) {
    removed_route = table->routes[index];
    table->routes[index] = NULL;
  }

  return removed_route;
}



/*int ripv2_route_table_add (ripv2_route_table_t * table, ripv2_route_t * route)
{
  int route_index = -1;

  if (table != NULL) {
    // Find an empty place in the route table 
    int i;
    for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
      if (table->routes[i] == NULL) {
        table->routes[i] = route;
        route_index = i;
        break;
      }
    }
  }

  return route_index;
}*/



/*ripv2_route_t * ripv2_route_table_remove (ripv2_route_table_t * table, int index)
{
  ripv2_route_t * removed_route = NULL;

  if ((table != NULL) && (index >= 0) && (index < RIPv2_ROUTE_TABLE_SIZE)) {
    removed_route = table->routes[index];
    table->routes[index] = NULL;
  }

  return removed_route;
}*/



ripv2_route_t * ripv2_route_table_lookup (ripv2_route_table_t * table,
                                         ipv4_addr_t addr)
{
  ripv2_route_t * best_route = NULL;
  int best_route_prefix = -1;

  if (table != NULL) {
    int i;
    for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
      ripv2_route_t * route_i = table->routes[i];
      if (route_i != NULL) {
        int route_i_lookup = ripv2_route_lookup(route_i, addr);
        if (route_i_lookup > best_route_prefix) {
          best_route = route_i;
          best_route_prefix = route_i_lookup;
        }
      }
    }
  }

  return best_route;
}



ripv2_route_t * ripv2_route_table_get (ripv2_route_table_t * table, int index)
{
  ripv2_route_t * route = NULL;

  if ((table != NULL) && (index >= 0) && (index < RIPv2_ROUTE_TABLE_SIZE)) {
    route = table->routes[index];
  }

  return route;
}



int ripv2_route_table_find
( ripv2_route_table_t * table, ipv4_addr_t subnet, ipv4_addr_t mask )
{
  int route_index = -2;

  if (table != NULL) {
    route_index = -1;
    int i;
    for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
      ripv2_route_t * route_i = table->routes[i];
      if (route_i != NULL) {
        int same_subnet =
          (memcmp(route_i->subnet_addr, subnet, IPv4_ADDR_SIZE) == 0);
        int same_mask =
          (memcmp(route_i->subnet_mask, mask, IPv4_ADDR_SIZE) == 0);

        if (same_subnet && same_mask) {
          route_index = i;
          break;
        }
      }
    }
  }

  return route_index;
}



void ripv2_route_table_free (ripv2_route_table_t * table)
{
  if (table != NULL) {
    int i;
    for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
      ripv2_route_t * route_i = table->routes[i];
      if (route_i != NULL) {
        table->routes[i] = NULL;
        ripv2_route_free(route_i);
      }
    }
    free(table);
  }
}



int ripv2_route_table_read (char * filename, ripv2_route_table_t * table)
{
  int read_routes = 0;

  FILE * routes_file = fopen(filename, "r");
  if (routes_file == NULL) {
    fprintf(stderr, "Error opening input RIPv2 Routes file \"%s\": %s.\n",
            filename, strerror(errno));
    return -1;
  }

  int linenum = 0;
  char line_buf[1024];
  int err = 0;

  while ((! feof(routes_file)) && (err==0)) {

    linenum++;

    /* Read next line of file */
    char* line = fgets(line_buf, 1024, routes_file);
    if (line == NULL) {
      break;
    }

    /* If this line is empty or a comment, just ignore it */
    if ((line_buf[0] == '\n') || (line_buf[0] == '#')) {
      err = 0;
      continue;
    }

    /* Parse route from line */
    ripv2_route_t* new_route = ripv2_route_read(filename, linenum, line);
    if (new_route == NULL) {
      err = -1;
      break;
    }

    /* Add new route to Route Table */
    if (table != NULL) {
      err = ripv2_route_table_add(table, new_route);
      if (err >= 0) {
	err = 0;
	read_routes++;
      }
    }
  } /* while() */

  if (err == -1) {
    read_routes = -1;
  }

  /* Close IP Route Table file */
  fclose(routes_file);

  return read_routes;
}



int ripv2_route_table_output (ripv2_route_table_t * table, FILE * out)
{
  int err;

  int i;
  for (i=0; i<RIPv2_ROUTE_TABLE_SIZE; i++) {
    ripv2_route_t * route_i = ripv2_route_table_get(table, i);
    if (route_i != NULL) {
      err = ripv2_route_output(route_i, i, out);
      if (err == -1) {
	return -1;
      }
    }
  }

  return 0;
}



int ripv2_route_table_write (ripv2_route_table_t * table, char * filename)
{
  int num_routes = 0;

  FILE * routes_file = fopen(filename, "w");
  if (routes_file == NULL) {
    fprintf(stderr, "Error opening output RIPv2 Routes file \"%s\": %s.\n",
            filename, strerror(errno));
    return -1;
  }

  fprintf(routes_file, "# %s\n", filename);
  fprintf(routes_file, "#\n");

  if (table != NULL) {
    num_routes = ripv2_route_table_output (table, routes_file);
    if (num_routes == -1) {
      fprintf(stderr, "Error writing RIPv2 Routes file \"%s\": %s.\n",
              filename, strerror(errno));
      return -1;
    }
  }

  fclose(routes_file);

  return num_routes;
}



void ripv2_route_table_print (ripv2_route_table_t * table )
{
  if (table != NULL) {
    ripv2_route_table_output (table, stdout);
  }
}