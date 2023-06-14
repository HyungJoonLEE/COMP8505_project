#include "victim.h"
#include "extern.h"


struct sockaddr_in serv_addr;
pid_t pid;
pcap_t* nic_fd;

int main(int argc, char *argv[]) {
    struct options_victim opts;
    struct sockaddr_in attacker_address;
    char buffer[256] = {0};
    char receive[256] = {0};
    int attacker_address_size = sizeof(struct sockaddr_in);
    fd_set read_fds, copy_fds;
    int fd_max, fd_num;
    struct timeval timeout;
    int exit_flag = 0;

    program_setup();
    options_victim_init(&opts);
    initialize_victim_server(&opts);

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
                    if (strcmp(receive, EXIT) == 0) {
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

