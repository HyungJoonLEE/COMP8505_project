#ifndef COMP8505_PROJECT_ATTACKER_H
#define COMP8505_PROJECT_ATTACKER_H

#include "common.h"

struct options_attacker {
    char victim_ip[16];
    unsigned char victim_MAC[6];
    int victim_socket;
    char victim_instruction[128];
    char* interface;
    char command[128];
    char encrypt_command[128];
    int attacker_socket;
    bool exit_flag
};


void options_attacker_init(struct options_attacker *opts);
void get_victim_IP(struct options_attacker *opts);
void get_victim_MAC(struct options_attacker *opts);
void create_attacker_socket(struct options_attacker *opts, struct sockaddr_in *victim_address);

void get_instruction(struct options_attacker *opts);
void get_protocol(struct options_attacker *opts);
bool confirm_user_input(struct options_attacker *opts);
bool is_valid_ipaddress(char *ip_address);
void encrypt_and_create_instruction_file(struct options_attacker *opts);
void send_instruction(struct options_attacker *opts);
int register_victim_socket(struct options_attacker *opts);

#endif //COMP8505_PROJECT_ATTACKER_H
