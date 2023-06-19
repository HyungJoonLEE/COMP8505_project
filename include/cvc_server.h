#ifndef COMP8505_PROJECT_CVC_SERVER_H
#define COMP8505_PROJECT_CVC_SERVER_H

#include "common.h"
#define CVC_FILTER "udp and dst port 55000"

struct options_cvc{
    char victim_ip[INET_ADDRSTRLEN];
    char attacker_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    int cvc_socket;
    int client_socket[BACKLOG];
    int client_count;
};


void options_cvc_init(struct options_cvc *opts);
void options_cvc_process(struct options_cvc *opts);
void add_new_client(struct options_cvc *opts, int client_socket, struct sockaddr_in *new_client_address);
int get_max_socket_number(struct options_cvc *opts);

#endif //COMP8505_PROJECT_CVC_SERVER_H
