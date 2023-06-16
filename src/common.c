#include "common.h"
#include "extern.h"


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
