#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdarg.h>
#include "policy.h"

typedef int (*open_t)(const char *, int, ...);
static open_t real_open = NULL;

/* Fetch original glibc open() */
static open_t get_real_open() {
    if (!real_open)
        real_open = (open_t)dlsym(RTLD_NEXT, "open");
    return real_open;
}

/* Log actions to stderr and logfile */
static void log_action(const char *msg) {
    char buf[1024];
    int len = snprintf(buf, sizeof(buf), "%s\n", msg);
    syscall(SYS_write, STDERR_FILENO, buf, (size_t)len);

    open_t o = get_real_open();
    if (!o) return;

    int fd = o("/u01/app/oracle/syscall-project/logs/syscall.log",
               O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (fd >= 0) {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);

        char timebuf[64];
        strftime(timebuf, sizeof(timebuf),
                 "%Y-%m-%d %H:%M:%S", &tm);

        char line[2048];
        int n = snprintf(line, sizeof(line),
                         "[%s] %s\n", timebuf, msg);

        syscall(SYS_write, fd, line, (size_t)n);
        syscall(SYS_close, fd);
    }
}