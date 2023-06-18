#include "common.h"
#include "extern.h"


void program_setup(void) {
    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


unsigned short hide_data(unsigned short ch) {
    uint16_t key = 0xABCD;
    return ch ^ key;
}


void sig_handler(int signum) {
    //Return type of the handler function should be void
    pid = getpid();
    printf("Ctrl + C pressed\n Exit program \n");
    kill(pid, SIGUSR1);
}


_Noreturn void fatal_errno(const char *file, const char *func, size_t line,
                           int err_code, int exit_code) {
    const char *msg;

    msg = strerror(err_code); // NOLINT(concurrency-mt-unsafe)
    fprintf(stderr, "Error (%s @ %s:%zu %d) - %s\n", file, func, line, err_code,
            msg);    // NOLINT(cert-err33-c)
    exit(exit_code); // NOLINT(concurrency-mt-unsafe)
}


_Noreturn void fatal_message(const char *file, const char *func, size_t line,
                             const char *msg, int exit_code) {
    fprintf(stderr, "Error (%s @ %s:%zu) - %s\n", file, func, line,
            msg);    // NOLINT(cert-err33-c)
    exit(exit_code); // NOLINT(concurrency-mt-unsafe)
}


unsigned int host_convert(char *hostname) {
    static struct in_addr i;
    struct hostent *h;
    i.s_addr = inet_addr(hostname);
    if(i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if(h == NULL)
        {
            fprintf(stderr, "cannot resolve %s\n", hostname);
            exit(0);
        }
        memcpy(h->h_name, (char *)&i.s_addr, (unsigned long) h->h_length);
    }
    return i.s_addr;
}


uint16_t calculate_checksum(void *header, int header_size) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)header;

    while (header_size > 1) {
        sum += *ptr++;
        header_size -= 2;
    }

    if (header_size > 0) {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}


void check_root_user(void) {
    if(geteuid() != 0) {
        printf("\nYou need to be root to run this.\n\n");
        exit(0);
    }
}


uint16_t generate_random_port(void) {
    int min_port = 1024;
    int max_port = 65535;

    srand((unsigned)time(NULL));
    return (uint16_t) ((rand() % (max_port - min_port + 1)) + min_port);
}

