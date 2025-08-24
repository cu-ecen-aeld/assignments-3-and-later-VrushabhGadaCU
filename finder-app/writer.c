#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "syslog.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        syslog(LOG_ERR, "Please enter First argument as File path and second as Text to save in te file");
        return 1;
    }
    if (argc >= 4)
    {
        syslog(LOG_ERR, "Only two arguments are used first as File path and second as Text to save in te file\n");
    }

    int fd;

    fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd == -1)
    {
        syslog(LOG_ERR, "Error opening file: %s", strerror(errno));
        return 1;
    }
    syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
    ssize_t nr;
    nr = write(fd, argv[2], strlen(argv[2]));
    if (nr == -1)
    {
        syslog(LOG_ERR, "Error writing to file: %s", strerror(errno));
        close(fd);
        return 1;
    }

    close(fd);
}