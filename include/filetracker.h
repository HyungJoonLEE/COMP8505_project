#ifndef COMP8505_PROJECT_FILETRACKER_H
#define COMP8505_PROJECT_FILETRACKER_H

#include "common.h"
#include "options.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * ( EVENT_SIZE + 16 ))

int track_file(struct options_victim* opts);
void send_packet(struct options_victim* opts, int size, const char *str);
void remove_client(struct options_victim *opts);


#endif //COMP8505_PROJECT_FILETRACKER_H
