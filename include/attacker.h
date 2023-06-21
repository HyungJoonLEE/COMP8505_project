#ifndef COMP8505_PROJECT_ATTACKER_H
#define COMP8505_PROJECT_ATTACKER_H

#include "common.h"

#define FILTER "udp and src port 53000"

void options_attacker_init(struct options_attacker *opts);
void get_victim_ip(struct options_attacker *opts);
void get_my_ip(char* nic_interface, struct options_attacker *opts);
void create_attacker_udp_socket(struct options_attacker *opts, struct sockaddr_in *victim_address);
void create_attacker_cnc_socket(struct options_attacker *opts, struct sockaddr_in *cnc_address);
void create_attacker_tcp_socket(struct options_attacker *opts, struct sockaddr_in *tcp_address);
unsigned short create_udp_header(struct udphdr* uh);
unsigned short create_ip_header(struct iphdr* ih, char c, struct options_attacker *opts);
void* udp_select_call(void* arg);
void* tcp_select_call(void* arg);
void* cnc_checker(void* arg);
void cnc_select_call(struct options_attacker *opts, struct sockaddr_in cnc_address);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
bool is_valid_ipaddress(char *ip_address);


#endif //COMP8505_PROJECT_ATTACKER_H
