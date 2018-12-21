#ifndef TIME_H
#define TIME_H

#define DEFAULT_TIMEOUT 60

#include <time.h>

extern int timeout_seconds;

void *close_timeout_connectionLoop(void *nullPtr);

#endif