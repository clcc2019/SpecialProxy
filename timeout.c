#include "main.h"
#include "http.h"
#include "time.h"

unsigned int timeout_seconds;

void *close_timeout_connectionLoop(void *nullPtr)
{
    time_t currentTime;
    int i, recv_return;
    char c;

    while (1)
    {
        sleep(1);
        currentTime = time(NULL);
        for (i = 0; i < MAX_CONNECTION; i += 2)
        {
            if (cts[i].fd > -1 && cts[i].is_ssl == 0 && cts[i].last_event_time != 0 && currentTime - cts[i].last_event_time >= (time_t)timeout_seconds)
            {
                recv_return = recv(cts[i].fd, &c, 1, MSG_PEEK);
                if (recv_return == 0 && errno != EAGAIN)
                    close_connection(cts + i);
            }
        }
    }
}