#ifndef TIME_H
#define TIME_H

#define DEFAULT_TIMEOUT 35

#include <time.h>

extern unsigned int timeout_seconds;

void *close_timeout_connectionLoop(void *nullPtr);

#endif