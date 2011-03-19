#define LOG_TAG "su"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <pwd.h>

#include <private/android_filesystem_config.h>
#include <cutils/log.h>

extern char* _mktemp(char*); /* mktemp doesn't link right.  Don't ask me why. */

#include "su.h"

static char shell[PATH_MAX];
static unsigned req_uid = 0;

static struct su_initiator su_from = {
    .pid = -1,
    .uid = 0,
    .bin = "",
    .args = "",
};

static struct su_request su_to = {
    .uid = AID_ROOT,
    .command = DEFAULT_COMMAND,
};

static int from_init(struct su_initiator *from)
{
    char path[PATH_MAX], exe[PATH_MAX];
    char args[4096], *argv0, *argv_rest;
    int fd;
    ssize_t len;
    int i;

    from->uid = getuid();
    from->pid = getppid();

    /* Get the command line */
    snprintf(path, sizeof(path), "/proc/%u/cmdline", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        PLOGE("Opening command line");
        return -1;
    }
    len = read(fd, args, sizeof(args));
    close(fd);
    if (len < 0 || len == sizeof(args)) {
        PLOGE("Reading command line");
        return -1;
    }

    argv0 = args;
    argv_rest = NULL;
    for (i = 0; i < len; i++) {
        if (args[i] == '\0') {
            if (!argv_rest) {
                argv_rest = &args[i+1];
            } else {
                args[i] = ' ';
            }
        }
    }
    args[len] = '\0';

    if (argv_rest) {
        strncpy(from->args, argv_rest, sizeof(from->args));
        from->args[sizeof(from->args)-1] = '\0';
    } else {
        from->args[0] = '\0';
    }

    /* If this isn't app_process, use the real path instead of argv[0] */
    snprintf(path, sizeof(path), "/proc/%u/exe", from->pid);
    len = readlink(path, exe, sizeof(exe));
    if (len < 0) {
        PLOGE("Getting exe path");
        return -1;
    }
    exe[len] = '\0';
    if (strcmp(exe, "/system/bin/app_process")) {
        argv0 = exe;
    }

    strncpy(from->bin, argv0, sizeof(from->bin));
    from->bin[sizeof(from->bin)-1] = '\0';

    return 0;
}

static void deny(void)
{
    struct su_initiator *from = &su_from;
    struct su_request *to = &su_to;

    LOGW("request rejected (%u->%u %s)", from->uid, to->uid, to->command);
    fprintf(stderr, "%s\n", strerror(EACCES));
    exit(-1);
}

static void allow(int notifications)
{
    struct su_initiator *from = &su_from;
    struct su_request *to = &su_to;
    char *exe = NULL;

    if (!strcmp(shell, "")) {
        strcpy(shell , "/system/bin/sh");
    }
    exe = strrchr (shell, '/') + 1;
    setgroups(0, NULL);
    setresgid(to->uid, to->uid, to->uid);
    setresuid(to->uid, to->uid, to->uid);
    LOGD("%u %s executing %u %s using shell %s : %s", from->uid, from->bin, to->uid, to->command, shell, exe);
    if (strcmp(to->command, DEFAULT_COMMAND)) {
        execl(shell, exe, "-c", to->command, (char*)NULL);
    } else {
        execl(shell, exe, "-", (char*)NULL);
    }
    PLOGE("exec");
    exit(-1);
}

int main(int argc, char *argv[])
{
    struct stat st;
    char buf[64], *result;
    int i;
    int dballow;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c")) {
            if (++i < argc) {
                su_to.command = argv[i];
            } else {
                deny();
            }
        } else if (!strcmp(argv[i], "-s")) {
            if (++i < argc) {
                strcpy(shell, argv[i]);
            } else {
                deny();
            }
        } else if (!strcmp(argv[i], "-v")) {
            printf("%s\n", VERSION);
            exit(-1);
        } else if (!strcmp(argv[i], "-")) {
            ++i;
            break;
        } else {
            break;
        }
    }
    if (i < argc-1) {
        deny();
    }
    if (i == argc-1) {
        struct passwd *pw;
        pw = getpwnam(argv[i]);
        if (!pw) {
            su_to.uid = atoi(argv[i]);
        } else {
            su_to.uid = pw->pw_uid;
        }
    }

    from_init(&su_from);

    if (su_from.uid == AID_ROOT)
        allow(0);

    if (st.st_gid != st.st_uid)
    {
        LOGE("Bad uid/gid %d/%d for Superuser Requestor application", (int)st.st_uid, (int)st.st_gid);
        deny();
    }

    req_uid = st.st_uid;

    if (from_init(&su_from) < 0) {
        deny();
    }

    allow(0);

    return -1;
}
