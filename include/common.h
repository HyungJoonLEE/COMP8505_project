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
#include <sys/inotify.h>
#include <unistd.h>
#include "extern.h"
#include "options.h"


#define UDP_SEND_SIZE 28
#define TCP_SEND_SIZE 40
#define TRUE 1
#define FALSE 0
#define MASK "bash_project"
#define QUIT "quit"



void check_root_user(void);
void program_setup(void);
uint16_t hide_data(uint16_t input);
void sig_handler(int signum);
unsigned int host_convert(char *hostname);
uint16_t calculate_checksum(void *header, int header_size);
void create_socket(void *arg, char flag, char protocol, char* ip, uint16_t port);
unsigned short create_udp_header(struct udphdr* uh, uint16_t sport, uint16_t dport);
unsigned short create_tcp_header(struct tcphdr* th, uint16_t sport, uint16_t dport);
unsigned short create_ip_header(struct iphdr* ih, void *arg, char flag, char c, char protocol);

#endif //COMP8505_PROJECT_COMMON_H
