#ifndef SU_h
#define SU_h 1

#define DEFAULT_COMMAND "/system/bin/sh"

#define VERSION "2.3.1-efg"

struct su_initiator {
    pid_t pid;
    unsigned uid;
    char bin[PATH_MAX];
    char args[4096];
};

struct su_request {
    unsigned uid;
    char *command;
};

#if 0
#undef LOGE
#define LOGE(fmt,args...) fprintf(stderr, fmt , ## args )
#undef LOGD
#define LOGD(fmt,args...) fprintf(stderr, fmt , ## args )
#undef LOGW
#define LOGW(fmt,args...) fprintf(stderr, fmt , ## args )
#endif

#define PLOGE(fmt,args...) LOGE(fmt " failed with %d: %s" , ## args , errno, strerror(errno))
#define PLOGEV(fmt,err,args...) LOGE(fmt " failed with %d: %s" , ## args , err, strerror(err))

#endif
