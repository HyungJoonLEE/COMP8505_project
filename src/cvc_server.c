#include "common.h"
#include "cvc_server.h"



#define BUF_SIZE 500


int main(int argc, char *argv[]) {
    struct options_cvc opts;
    struct sockaddr_in client_address;
    int client_socket;
    char buffer[256] = {0};
    char receive[256] = {0};
    socklen_t client_address_size = sizeof(struct sockaddr_in);
    fd_set read_fds, copy_fds;
    int fd_max, fd_num;
    struct timeval timeout;
    int exit_flag = 0;
    int j = 0;

    options_cvc_init(&opts);
    options_cvc_process(&opts);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(opts.cvc_socket, &read_fds);
    fd_max = opts.cvc_socket;

    while (1) {
        copy_fds = read_fds;
        fd_num = select(fd_max + 1, &copy_fds, 0, 0, &timeout);
        if (fd_num == -1) {
            perror("Select() failed");
            exit(EXIT_FAILURE);
        } else if (fd_num == 0) continue; // time out

        for (int i = 0; i < fd_max + 1; i++) {
            if (FD_ISSET(i, &copy_fds)) {
                if (i == opts.cvc_socket) {
                    client_socket = accept(opts.cvc_socket, (struct sockaddr *) &client_address,
                                                 &client_address_size);
                    add_new_client(&opts, client_socket, &client_address);
                    FD_SET(client_socket, &read_fds);
                    fd_max = get_max_socket_number(&opts);
                    j++;
                }
                if (i == opts.client_socket[0]) {
                    read(opts.client_socket[0], receive, sizeof(receive));
                    write(opts.client_socket[1], receive, sizeof(receive));
                    printf("PACKET = [ %s ]\n", receive);
                    memset(receive, 0, sizeof(char) * 256);
                }
            }
        }
    }
    close(opts.cvc_socket);
    return EXIT_SUCCESS;
}

void options_cvc_init(struct options_cvc *opts) {
    memset(opts, 0, sizeof(struct options_cvc));
}


void options_cvc_process(struct options_cvc *opts) {
    struct sockaddr_in proxy_address;
    int option = TRUE;

    opts->cvc_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (opts->cvc_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    proxy_address.sin_family = AF_INET;
    proxy_address.sin_port = htons(CVC_PORT);
    proxy_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (proxy_address.sin_addr.s_addr == (in_addr_t) -1) {
        fatal_errno(__FILE__, __func__, __LINE__, errno, 2);
    }

    option = 1;
    setsockopt(opts->cvc_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    setsockopt(opts->cvc_socket, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(option));


    if (bind(opts->cvc_socket, (struct sockaddr *) &proxy_address, sizeof(struct sockaddr_in)) == -1) {
        perror("bind() ERROR\n");
        exit(EXIT_FAILURE);
    }


    if (listen(opts->cvc_socket, BACKLOG) == -1) {
        perror("listen() ERROR\n");
        exit(EXIT_FAILURE);
    }
}


void add_new_client(struct options_cvc *opts, int client_socket, struct sockaddr_in *client_address) {
    char buffer[20];

    inet_ntop(AF_INET, &client_address->sin_addr, buffer, sizeof(buffer));
    printf("New client: [ %s ]\n", buffer);

    opts->client_socket[opts->client_count] = client_socket;
    opts->client_count++;
    printf("Current client count = %d\n", opts->client_count);
}



int get_max_socket_number(struct options_cvc *opts) {
    int max = 3;
    int i;

    for (i = 0; i < opts->client_count; i++)
        if (opts->client_socket[i] > max)
            max = opts->client_socket[i];

    return max;
}
