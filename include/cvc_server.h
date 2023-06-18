#ifndef COMP8505_PROJECT_CVC_SERVER_H
#define COMP8505_PROJECT_CVC_SERVER_H

#include "common.h"
#define CVC_FILTER "udp and dst port 55000"

struct options_cvc{
    char victim_ip[INET_ADDRSTRLEN];
    char attacker_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    int cvc_socket;
};

void options_cvc_init(struct options_cvc *opts);
void initialize_cvc_server(struct options_cvc *opts);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_cvc_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif //COMP8505_PROJECT_CVC_SERVER_H
