#ifndef COMP8505_PROJECT_OPTIONS_H
#define COMP8505_PROJECT_OPTIONS_H

#include <netinet/in.h>
#include <stdbool.h>


#define ATC_UDP_PORT 35000
#define VIC_UDP_PORT 53000
#define ATC_TCP_PORT 25000
#define VIC_TCP_PORT 52000

#define DEFAULT_COUNT 10000
#define S_ARR_SIZE 64
#define OUTPUT_SIZE 20000


struct options_attacker {
    char dest_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    char victim_instruction[64];
    char target_directory[64];
    int tcp_socket;
    int udp_socket;
    struct sockaddr_in udpsa;
    struct sockaddr_in tcpsa;
};


struct options_victim {
    char dest_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    int udp_socket;
    int tcp_socket;
    int attacker_socket;
    struct sockaddr_in udpsa;
    struct sockaddr_in tcpsa;
    char received_buffer[S_ARR_SIZE];
    char instruction[S_ARR_SIZE];
    char sending_buffer[OUTPUT_SIZE];
    char target_directory[64];
    int file_count;
    LinkedList * file_list;
    bool ip_flag;
    bool keylogger;
    bool target;
};

#endif //COMP8505_PROJECT_OPTIONS_H
