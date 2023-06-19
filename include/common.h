#ifndef COMP8505_PROJECT_COMMON_H
#define COMP8505_PROJECT_COMMON_H

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/if_packet.h>
#include <linux/input.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <openssl/blowfish.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <regex.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "extern.h"

#define ATTACKER_PORT 52000
#define DEFAULT_PORT 53000
#define VICTIM_PORT 54000
#define CVC_PORT 55000

#define DEFAULT_COUNT 10000
#define S_ARR_SIZE 64
#define OUTPUT_SIZE 20000
#define RECEIVE_SIZE 256
#define SEND_SIZE 28
#define BACKLOG 5
#define TRUE 1
#define FALSE 0
#define MASK "bash_project"
#define QUIT "quit"


struct options_attacker {
    char victim_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    char cvc_ip[INET_ADDRSTRLEN];
    char victim_instruction[64];
    int attacker_socket_udp;
    int attacker_socket_tcp;
    bool cvc;
};


struct options_victim {
    char attacker_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    char cvc_ip[INET_ADDRSTRLEN];
    int victim_socket;
    int cvc_socket;
    uint16_t attacker_port;
    char received_buffer[S_ARR_SIZE];
    char instruction[S_ARR_SIZE];
    char sending_buffer[OUTPUT_SIZE];
    struct sockaddr_in cvc_addr;
    bool ip_flag;
    bool keylogger;
    bool cvc;
};

typedef struct recv_udp {
    struct iphdr ip;
    struct udphdr udp;
} recv_pkt;



void check_root_user(void);
void program_setup(void);
uint16_t hide_data(uint16_t input);
void sig_handler(int signum);
_Noreturn void fatal_errno(const char *file, const char *func, size_t line, int err_code, int exit_code);
_Noreturn void fatal_message(const char *file, const char *func, size_t line, const char *msg, int exit_code);
unsigned int host_convert(char *hostname);
uint16_t calculate_checksum(void *header, int header_size);
uint16_t generate_random_port(void);


#endif //COMP8505_PROJECT_COMMON_H
