#ifndef COMP8505_PROJECT_COMMON_H
#define COMP8505_PROJECT_COMMON_H

#include <stdio.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stddef.h>
#include <limits.h>
#include <sys/types.h>
#include <getopt.h>
#include <regex.h>
#include <inttypes.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <linux/if_packet.h>
#include <openssl/blowfish.h>
#include "extern.h"

#define DEFAULT_PORT 53000
#define RECEIVE_SIZE 2048
#define BACKLOG 5
#define TRUE 1
#define FALSE 0
#define MASK "bash_project"
#define EXIT "exit"
#define CONNECTION_SUCCESS "Successfully connected to the target"

void check_root_user(void);
char encrypt_decrypt(char input);
void sig_handler(int signum);
_Noreturn void fatal_errno(const char *file, const char *func, size_t line, int err_code, int exit_code);
_Noreturn void fatal_message(const char *file, const char *func, size_t line, const char *msg, int exit_code);

#endif //COMP8505_PROJECT_COMMON_H
