/* this first #define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include "policy.h"

typedef int (*open_t)(const char *, int);

int open(const char *pathname, int flags) {
    load_policy("policy.json");

    if (is_blocked(pathname)) {
        printf("[BLOCKED] Access denied: %s\n", pathname);
        return -1;
    }

    printf("[INFO] File access: %s\n", pathname);

    open_t original_open = (open_t)dlsym(RTLD_NEXT, "open");
    return original_open(pathname, flags);
}*/
/* this is second #define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "policy.h"

typedef int (*open_t)(const char *, int);

int ask_permission(const char *pathname) {
    printf("\n[PERMISSION REQUEST]\n");
    printf("Application is trying to access: %s\n", pathname);
    printf("1) Allow once\n");
    printf("2) Block once\n");
    printf("3) Always allow\n");
    printf("4) Always block\n");
    printf("Choose option: ");

    int choice;
    scanf("%d", &choice);
    return choice;
}

int open(const char *pathname, int flags) {
    load_policy("policy.json");

    // First check permanent block list
    if (is_blocked(pathname)) {
        printf("[BLOCKED] This file is permanently blocked: %s\n", pathname);
        return -1;
    }

    int decision = ask_permission(pathname);

    if (decision == 2) {
        printf("[BLOCKED ONCE] Access denied: %s\n", pathname);
        return -1;
    }

    if (decision == 4) {
        add_to_blocklist(pathname);
        printf("[PERMANENT BLOCK] Added to block list: %s\n", pathname);
        return -1;
    }

    if (decision == 3) {
        add_to_allowlist(pathname);
        printf("[PERMANENT ALLOW] Added to allow list: %s\n", pathname);
    }

    printf("[ALLOWED] Access granted: %s\n", pathname);

    open_t original_open = (open_t)dlsym(RTLD_NEXT, "open");
    return original_open(pathname, flags);
}
*/
/* second for auth update
;
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <time.h>
#include "policy.h"
#include <stdarg.h>

typedef int (*open_t)(const char *, int, ...);
static open_t real_open = NULL;

static open_t get_real_open() {
    if (!real_open) real_open = (open_t)dlsym(RTLD_NEXT, "open");
    return real_open;
}

static void log_action(const char *msg) {
    // write to stderr (safe) and append to logs/syscall.log using the original open()
    char buf[1024];
    int len = snprintf(buf, sizeof(buf), "%s\n", msg);
    if (len > 0) syscall(SYS_write, STDERR_FILENO, buf, (size_t)len);

    // try append to logs/syscall.log via original open to avoid recursion
    open_t o = get_real_open();
    if (o) {
        int fd = o("/u01/app/oracle/syscall-project/logs/syscall.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            time_t t = time(NULL);
            struct tm tm; localtime_r(&t, &tm);
            char timebuf[64];
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);
            char line[2048];
            int n = snprintf(line, sizeof(line), "[%s] %s\n", timebuf, msg);
            syscall(SYS_write, fd, line, (size_t)n);
            syscall(SYS_close, fd);
        }
    }
}

static int ask_permission_interactive(const char *pathname) {
    printf("\n[PERMISSION REQUEST]\n");
    printf("Application is trying to access: %s\n", pathname);
    printf("1) Allow once\n");
    printf("2) Block once\n");
    printf("3) Always allow\n");
    printf("4) Always block\n");
    printf("Choose option: ");
    fflush(stdout);

    int choice = 0;
    if (scanf("%d", &choice) != 1) {
        // if input fails, default to block
        while (getchar() != '\n'); // clear
        return 2;
    }
    return choice;
}

int open(const char *pathname, int flags, ...) {
    // Ensure policy loaded
    load_policy("policy.json");

    // If file in allowlist -> allow silently
    if (is_allowed(pathname)) {
        char m[1024];
        snprintf(m, sizeof(m), "[ALLOWED (whitelist)] %s", pathname);
        log_action(m);
        open_t orig = get_real_open();
        if (!orig) return -1;
        // handle mode argument if O_CREAT
        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            int mode = va_arg(ap, int);
            va_end(ap);
            return orig(pathname, flags, mode);
        } else {
            return orig(pathname, flags);
        }
    }

    // If file in permanent block list -> block silently
    if (is_blocked(pathname)) {
        char m[1024];
        snprintf(m, sizeof(m), "[BLOCKED (perm)] %s", pathname);
        log_action(m);
        return -1;
    }

    // If process not connected to a TTY (non-interactive), default to deny (safe)
    if (!isatty(STDIN_FILENO)) {
        char m[1024];
        snprintf(m, sizeof(m), "[NON-INTERACTIVE DEFAULT DENY] %s", pathname);
        log_action(m);
        return -1;
    }

    // Interactive: ask the user
    int choice = ask_permission_interactive(pathname);

    if (choice == 2) {
        char m[1024];
        snprintf(m, sizeof(m), "[BLOCKED ONCE] %s", pathname);
        log_action(m);
        return -1;
    }
    if (choice == 4) {
        add_to_blocklist(pathname);
        char m[1024];
        snprintf(m, sizeof(m), "[PERMANENT BLOCK] %s", pathname);
        log_action(m);
        return -1;
    }
    if (choice == 3) {
        add_to_allowlist(pathname);
        char m[1024];
        snprintf(m, sizeof(m), "[PERMANENT ALLOW] %s", pathname);
        log_action(m);
        // continue to open
    }

    // Allowed once or after adding to allowlist -> call original open
    open_t orig = get_real_open();
    if (!orig) return -1;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        int mode = va_arg(ap, int);
        va_end(ap);
        int fd = orig(pathname, flags, mode);
        char m[1024]; snprintf(m, sizeof(m), "[ALLOWED] %s (fd=%d)", pathname, fd);
        log_action(m);
        return fd;
    } else {
        int fd = orig(pathname, flags);
        char m[1024]; snprintf(m, sizeof(m), "[ALLOWED] %s (fd=%d)", pathname, fd);
        log_action(m);
        return fd;
    }
}
*/
/* this is one #define _GNU_SOURCE
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

// Get original open() from glibc
static open_t get_real_open() {
    if (!real_open)
        real_open = (open_t)dlsym(RTLD_NEXT, "open");
    return real_open;
}

// Logging function (writes to stderr + logfile)
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
        struct tm tm; localtime_r(&t, &tm);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

        char line[2048];
        int n = snprintf(line, sizeof(line), "[%s] %s\n", timebuf, msg);

        syscall(SYS_write, fd, line, (size_t)n);
        syscall(SYS_close, fd);
    }
}

// User permission popup
static int ask_permission(const char *pathname) {
    printf("\n[PERMISSION REQUEST]\n");
    printf("Application tried to access: %s\n", pathname);
    printf("1) Allow once\n");
    printf("2) Block once\n");
    printf("3) Always allow\n");
    printf("4) Always block\n");
    printf("Choose option: ");
    fflush(stdout);

    int choice = 0;
    scanf("%d", &choice);
    return choice;
}

// MAIN INTERCEPTOR FUNCTION
int open(const char *pathname, int flags, ...) {
    load_policy("policy.json");

    // Always allowed (from policy)
    if (is_allowed(pathname)) {
        char m[256];
        snprintf(m, sizeof(m), "[ALLOWED (whitelist)] %s", pathname);
        log_action(m);

        open_t orig = get_real_open();
        if (!orig) return -1;

        if (flags & O_CREAT) {
            va_list ap; va_start(ap, flags);
            int mode = va_arg(ap, int);
            va_end(ap);
            return orig(pathname, flags, mode);
        }
        return orig(pathname, flags);
    }

    // Always blocked (from policy)
    if (is_blocked(pathname)) {
        char m[256];
        snprintf(m, sizeof(m), "[BLOCKED (perm)] %s", pathname);
        log_action(m);
        return -1;
    }

    // If not running in terminal → DENY (safe default)
    if (!isatty(STDIN_FILENO)) {
        char m[256];
        snprintf(m, sizeof(m), "[NON-INTERACTIVE DEFAULT DENY] %s", pathname);
        log_action(m);
        return -1;
    }

    // Ask user permission
    int choice = ask_permission(pathname);

    // BLOCK ONCE
    if (choice == 2) {
        char m[256];
        snprintf(m, sizeof(m), "[BLOCKED ONCE] %s", pathname);
        log_action(m);
        return -1;
    }

    // ALWAYS BLOCK
    if (choice == 4) {
        add_to_blocklist(pathname);
        char m[256];
        snprintf(m, sizeof(m), "[PERMANENT BLOCK] %s", pathname);
        log_action(m);

        return -1;
    }

    // ALLOW ONCE
    if (choice == 1) {
        load_password("/u01/app/oracle/syscall-project/auth/pass.txt", "r");

        if (!authenticate()) {
            printf("[ACCESS BLOCKED: Wrong password]\n");
            log_action("[AUTH FAILED - BLOCKED]");
            return -1;
        }

        log_action("[AUTH SUCCESS - ALLOW ONCE]");
    }

    // ALWAYS ALLOW
    if (choice == 3) {
        load_password("auth/pass.txt");

        if (!authenticate()) {
            printf("[ACCESS BLOCKED: Wrong password]\n");
            log_action("[AUTH FAILED - BLOCKED]");
            return -1;
        }

        add_to_allowlist(pathname);

        char m[256];
        snprintf(m, sizeof(m), "[PERMANENT ALLOW] %s", pathname);
        log_action(m);
    }

    // Finally, call original open()
    open_t orig = get_real_open();
    if (!orig) return -1;

    int fd;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        int mode = va_arg(ap, int);
        va_end(ap);
        fd = orig(pathname, flags, mode);
    } else {
        fd = orig(pathname, flags);
    }

    char m[256];
    snprintf(m, sizeof(m), "[ALLOWED] %s (fd=%d)", pathname, fd);
    log_action(m);

    return fd;
}
*/
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include "policy.h"

typedef int (*open_t)(const char *, int, ...);
static open_t real_open = NULL;

// Absolute paths
#define LOG_FILE "/u01/app/oracle/syscall-project/logs/syscall.log"
#define PASS_FILE "/u01/app/oracle/syscall-project/auth/pass.txt"

// Get original open() from glibc
static open_t get_real_open() {
    if (!real_open)
        real_open = (open_t)dlsym(RTLD_NEXT, "open");
    return real_open;
}

// Logging function (writes to stderr + logfile)
static void log_action(const char *msg) {
    char buf[1024];
    int len = snprintf(buf, sizeof(buf), "%s\n", msg);
    syscall(SYS_write, STDERR_FILENO, buf, (size_t)len);

    open_t o = get_real_open();
    if (!o) return;

    int fd = o(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        time_t t = time(NULL);
        struct tm tm; localtime_r(&t, &tm);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "[%Y-%m-%d %H:%M:%S]", &tm);
        dprintf(fd, "%s %s\n", timebuf, msg);
        close(fd);
    }
}

// Load password from file
static char *load_password() {
    FILE *fp = fopen(PASS_FILE, "r");
    if (!fp) return NULL;
    static char passwd[128];
    if (!fgets(passwd, sizeof(passwd), fp)) { fclose(fp); return NULL; }
    // Remove newline if exists
    passwd[strcspn(passwd, "\n")] = 0;
    fclose(fp);
    return passwd;
}

// Authenticate user input
static int authenticate() {
    char *correct = load_password();
    if (!correct) {
        log_action("[ERROR] Cannot open password file");
        return 0;
    }

    char input[128];
    printf("Enter password to allow access: ");
    if (!fgets(input, sizeof(input), stdin)) return 0;
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, correct) == 0) {
        log_action("[AUTH SUCCESS]");
        return 1;
    } else {
        log_action("[AUTH FAILED]");
        return 0;
    }
}

// The wrapped open() function
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    // Load policy
    load_policy(NULL);

    // Check if path is blocked
    if (is_blocked(pathname)) {
        log_action("[ACCESS BLOCKED - POLICY]");
        return -1;
    }

    // Check if path is allowed
    if (!is_allowed(pathname)) {
        char buf[256];
        snprintf(buf, sizeof(buf), "[PERMISSION REQUEST] Application tried to access: %s", pathname);
        log_action(buf);

        printf("%s\n", buf);
        printf("1) Allow once\n2) Block once\n3) Always allow\n4) Always block\nChoose option: ");

        int choice = 0;
        if (scanf("%d", &choice) != 1) choice = 0;
        while(getchar() != '\n'); // clear stdin

        int auth_pass = 1;
        if (choice == 1 || choice == 3) {
            auth_pass = authenticate();
        }

        if (!auth_pass) {
            add_to_blocklist(pathname);
            log_action("[ACCESS BLOCKED: Wrong password]");
            return -1;
        }

        if (choice == 3) add_to_allowlist(pathname);
        if (choice == 4) add_to_blocklist(pathname);
    }

    // Call the real open
    open_t o = get_real_open();
    if (!o) return -1;

    int fd = (flags & O_CREAT) ? o(pathname, flags, mode) : o(pathname, flags);

    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), "[ALLOWED] %s (fd=%d)", pathname, fd);
    log_action(logbuf);

    return fd;
}

