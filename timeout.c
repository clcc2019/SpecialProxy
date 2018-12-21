#include "main.h"
#include "http.h"
#include "time.h"

int timeout_seconds;

void *close_timeout_connectionLoop(void *nullPtr)
{
    int i;

    while (1)
    {
        sleep(1);
        for (i = 0; i < MAX_CONNECTION; i += 2)
            if (cts[i].fd > -1&& (int)(time(NULL) - cts[i].last_event_time) >= timeout_seconds)
                close_connection(cts + i);
    }
}