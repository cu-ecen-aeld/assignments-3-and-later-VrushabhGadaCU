#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#define BUFFER_SIZE 1024
#define DATA_FILE "/var/tmp/aesdsocketdata"
int waiting_for_connection = 0;
#include <signal.h>
int sockfd = -1;
int new_fd = -1;
int fd = -1;
char *packet = NULL;
struct addrinfo *servinfo;
volatile sig_atomic_t exit_flag = 0;
void clenanup(int return_code)
{
    if (packet)
    {
        free(packet);
        packet = NULL;
    }
    if (fd != -1)
        close(fd);
    if (new_fd != -1)
        close(new_fd);
    if (sockfd != -1)
        close(sockfd);
    if (servinfo)
        freeaddrinfo(servinfo);
    remove(DATA_FILE);
    exit(return_code); // Changed from exit(0) to exit(return_code)
}

void signal_handler(int sig)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    exit_flag = 1;

    if (waiting_for_connection)
    {
        clenanup(0);
    }
}

int main(int argc, char *argv[])
{
    int daemon_mode = 0;
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        daemon_mode = 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        return -1;
    }

    int status;
    struct addrinfo hints;

    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    if ((status = getaddrinfo(NULL, "9000", &hints, &servinfo)) != 0)
    {
        exit(1);
    }
    if (daemon_mode)
    {
        pid_t pid = fork();
        if (pid < 0)
        {
            syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
            return -1;
        }
        if (pid > 0)
        {
            // Parent exits
            return 0;
        }
        // Child continues
        if (setsid() == -1)
        {
            syslog(LOG_ERR, "setsid() failed: %s", strerror(errno));
            return -1;
        }
    }

    if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
    {
        clenanup(-1);
    }

    listen(sockfd, 1);

    socklen_t addr_size;
    struct sockaddr_storage their_addr;

    addr_size = sizeof their_addr;

    char client_ip[INET6_ADDRSTRLEN];
    while (!exit_flag)
    {
        waiting_for_connection = 1;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        waiting_for_connection = 0;
        // Handle both IPv4 and IPv6
        if (their_addr.ss_family == AF_INET)
        {
            struct sockaddr_in *s = (struct sockaddr_in *)&their_addr;
            inet_ntop(AF_INET, &s->sin_addr, client_ip, sizeof(client_ip));
        }
        else if (their_addr.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&their_addr;
            inet_ntop(AF_INET6, &s->sin6_addr, client_ip, sizeof(client_ip));
        }
        else
        {
            strncpy(client_ip, "unknown", sizeof(client_ip));
        }

        syslog(LOG_INFO, "Accepted connection from %s\n", client_ip);

        fd = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
        if (fd == -1)
        {
            clenanup(-1);
        }
        char buffer[BUFFER_SIZE];
        int packet_size = 0;
        int packet_capacity = BUFFER_SIZE;

        packet = malloc(BUFFER_SIZE);
        if (!packet)
        {
            clenanup(-1);
        }
        int bytes_received = 0;

        while (((bytes_received = recv(new_fd, buffer, sizeof(buffer) - 1, 0)) > 0) && (!exit_flag))
        {
            for (int i = 0; i < bytes_received; i++)
            {
                if (exit_flag)
                {
                    break;
                }
                // Expand packet buffer if needed
                if (packet_size >= packet_capacity - 1)
                {
                    packet_capacity *= 2;
                    char *new_packet = realloc(packet, packet_capacity);
                    if (!new_packet)
                    {
                        clenanup(-1);
                    }
                    packet = new_packet;
                }

                // Add character to packet
                packet[packet_size++] = buffer[i];

                // Check if packet is complete (newline found)
                if (buffer[i] == '\n')
                {
                    // Write packet to file
                    if (write(fd, packet, packet_size) == -1)
                    {
                        syslog(LOG_ERR, "Error writing to file: %s", strerror(errno));
                    }
                    close(fd);

                    // Open file for reading entire contents
                    fd = open(DATA_FILE, O_RDONLY);
                    if (fd == -1)
                    {
                        clenanup(-1);
                    }
                    // TODO: Check for if this works later
                    // Send entire file contents back to client
                    ssize_t bytes_read;
                    char read_buffer[BUFFER_SIZE];
                    while (((bytes_read = read(fd, read_buffer, sizeof(read_buffer))) > 0) && (!exit_flag))
                    {
                        ssize_t result = send(new_fd, read_buffer, bytes_read, 0);
                        if (result == -1)
                        {
                            clenanup(-1);
                        }
                    }
                    close(fd);

                    // Reset packet for next one and reopen file for append
                    packet_size = 0;
                    fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
                    if (fd == -1)
                    {
                        clenanup(-1);
                    }
                }
            }
        }

        // Clean up after recv loop ends
        if (packet)
        {
            free(packet);
            packet = NULL;
        }
        if (fd != -1)
        {
            close(fd);
            fd = -1;
        }
        if (new_fd != -1)
        {
            close(new_fd);
            new_fd = -1;
        }

        syslog(LOG_INFO, "Closed connection from %s", client_ip);
    }
    clenanup(0);
    return 0;
}