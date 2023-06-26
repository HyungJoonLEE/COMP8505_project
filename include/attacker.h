#ifndef COMP8505_PROJECT_ATTACKER_H
#define COMP8505_PROJECT_ATTACKER_H

#include "common.h"

#define FILTER "udp src port 53000 or tcp src port 52000"

void options_attacker_init(struct options_attacker *opts);
void get_my_ip(char* nic_interface, struct options_attacker *opts);
void get_dest_ip(struct options_attacker *opts);
void* input_select_call(void* arg);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void tokenize_file_info(struct options_attacker *opts, char* buffer);
//void tokenize_file_info(struct options_attacker *opts);
//void create_file(struct options_attacker *opts);
void create_file(struct options_attacker *opts);
bool is_valid_ipaddress(char *ip_address);


#endif //COMP8505_PROJECT_ATTACKER_H
