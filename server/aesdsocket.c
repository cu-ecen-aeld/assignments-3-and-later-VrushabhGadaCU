#define _GNU_SOURCE
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
#include <pthread.h>
#include <stdio.h>
#include <sys/queue.h>
#include <stdatomic.h>
#include <time.h>
#include <signal.h>

#define DATA_FILE "/var/tmp/aesdsocketdata"
pthread_t Timer_Thread_id;

volatile sig_atomic_t exitFlag = 0;
int ServerSocket = -1;
struct addrinfo *servinfo;
#define MAX_CLIENTS 10
pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct thread_list_s
{
    pthread_t thread_id;
    int client_fd;
    char client_ip[INET_ADDRSTRLEN];
    SLIST_ENTRY(thread_list_s)
    entries;
} thread_list_t;

SLIST_HEAD(slisthead, thread_list_s)
head;

void cleanup(int returnValue)
{
    printf("Cleaning up and exiting.\n");
    if (ServerSocket != -1)
    {
        close(ServerSocket);
        ServerSocket = -1;
    }

    pthread_join(Timer_Thread_id, NULL);
    printf("Joined timer thread.\n");

    thread_list_t *current = SLIST_FIRST(&head);
    thread_list_t *temp_var;

    while (current != NULL)
    {
        temp_var = SLIST_NEXT(current, entries);

        pthread_join(current->thread_id, NULL);
        SLIST_REMOVE(&head, current, thread_list_s, entries); // <-- FIXED
        free(current);

        current = temp_var;
    }

    exit(returnValue);
}

void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM)
    {
        shutdown(ServerSocket, SHUT_RDWR);
        syslog(LOG_INFO, "Caught signal, exiting");
        exitFlag = 1;
    }
}

void Set_Signal_Handlers(void)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
}

void Setup_Socket(void)
{
    ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (ServerSocket == -1)
    {
        exit(-1);
    }
    int status;
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
    if ((status = getaddrinfo(NULL, "9000", &hints, &servinfo)) != 0)
    {
        exit(-1);
    }

    if (bind(ServerSocket, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
    {
        exit(-1);
    }
    freeaddrinfo(servinfo);
}

void *timestamp_thread(void *arg)
{
    (void)arg;
    int fd;
    time_t now;
    struct tm *timeinfo;
    char timestamp[200];
    while (!exitFlag)
    {
        sleep(10);

        time(&now);
        timeinfo = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", timeinfo);

        pthread_mutex_lock(&mutex_lock);
        fd = open(DATA_FILE, O_WRONLY | O_APPEND | O_CREAT, 0664);
        if (fd == -1)
        {
            perror("open");
            syslog(LOG_ERR, "open");
            exit(1);
        }
        if (fd != -1)
        {
            ssize_t written = write(fd, timestamp, strlen(timestamp));
            if (written == -1)
            {
                syslog(LOG_ERR, "Error writing timestamp: %s", strerror(errno));
            }
            else if ((size_t)written < strlen(timestamp))
            {
                syslog(LOG_WARNING, "Partial write of timestamp");
            }
        }
        else
        {
            syslog(LOG_ERR, "Error opening file for timestamp: %s", strerror(errno));
        }
        close(fd);
        pthread_mutex_unlock(&mutex_lock);
    }
    return NULL;
}

void *client_handler(void *arg)
{
    thread_list_t *thread_data = (thread_list_t *)arg;
    int bytes_received;
    char buffer[1024];
    int SendData = 0;
    int fd;
    while (!exitFlag)
    {
        while (((bytes_received = recv(thread_data->client_fd, buffer, sizeof(buffer) - 1, 0)) > 0))
        {
            SendData = 0;
            if (bytes_received == -1)
            {
                break;
            }

            if (buffer[bytes_received - 1] == '\n')
            {
                SendData = 1;
            }

            pthread_mutex_lock(&mutex_lock);
            fd = open(DATA_FILE, O_WRONLY | O_APPEND | O_CREAT, 0664);
            if (fd == -1)
            {
                perror("open");
                syslog(LOG_ERR, "open");
                pthread_mutex_unlock(&mutex_lock);
                close(thread_data->client_fd);
                return NULL;
            }
            int ret = write(fd, buffer, bytes_received);
            if (ret == -1)
            {
                syslog(LOG_ERR, "Error writing to file %s: %s", DATA_FILE, strerror(errno));
                pthread_mutex_unlock(&mutex_lock);
                close(thread_data->client_fd);
                return NULL;
            }
            close(fd);
            pthread_mutex_unlock(&mutex_lock);

            if (SendData)
            {
                pthread_mutex_lock(&mutex_lock);
                fd = open(DATA_FILE, O_RDONLY);
                if (fd == -1)
                {
                    syslog(LOG_ERR, "open failed: %s", strerror(errno));
                    pthread_mutex_unlock(&mutex_lock);
                    close(thread_data->client_fd);
                    return NULL;
                }

                ssize_t rbytes;
                while ((rbytes = read(fd, buffer, sizeof(buffer))) > 0)
                {
                    ssize_t sent = send(thread_data->client_fd, buffer, rbytes, 0);
                    if (sent == -1)
                    {
                        syslog(LOG_ERR, "Error sending to %s: %s", thread_data->client_ip, strerror(errno));
                        break;
                    }
                }
                close(fd);
                pthread_mutex_unlock(&mutex_lock);
            }
        }
    }
    syslog(LOG_DEBUG, "Closed connection from %s\n", thread_data->client_ip);
    if (close(thread_data->client_fd))
    {
        perror("close");
        syslog(LOG_ERR, "close failed.");
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    int daemon_mode = 0;
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
        daemon_mode = 1;

    Set_Signal_Handlers();
    int fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0664);

    if (fd == -1)
    {
        syslog(LOG_ERR, "Failed to open %s: %s", DATA_FILE, strerror(errno));
        return -1;
    }
    close(fd);
    Setup_Socket();

    if (daemon_mode)
    {
        pid_t pid = fork();
        if (pid == -1)
        {
            syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
            return -1;
        }
        if (pid > 0)
        {
            // Parent exits
            return 0;
        }
    }
    int ret = listen(ServerSocket, MAX_CLIENTS);
    if (ret == -1)
    {
        perror("listen");
        syslog(LOG_ERR, "listen failed.");
        exit(1);
    }

    // Start timestamp thread
    ret = pthread_create(&Timer_Thread_id, NULL, timestamp_thread, NULL);
    if (ret)
    {
        perror("pthread_create");
        exit(1);
    }

    socklen_t addr_size;
    struct sockaddr_storage their_addr;
    addr_size = sizeof(their_addr);
    char client_ip[INET6_ADDRSTRLEN];
    SLIST_INIT(&head);

    while (!exitFlag)
    {
        int client_socket = accept(ServerSocket, (struct sockaddr *)&their_addr, &addr_size);
        if (client_socket < 0)
        {
            continue;
        }

        // Get client IP address
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

        thread_list_t *thread_node = (thread_list_t *)malloc(sizeof(thread_list_t));
        thread_node->client_fd = client_socket;
        strcpy(thread_node->client_ip, client_ip);

        if (pthread_create(&thread_node->thread_id, NULL, client_handler, thread_node) != 0)
        {
            perror("Thread creation failed");
            close(client_socket);
            continue;
        }
        SLIST_INSERT_HEAD(&head, thread_node, entries);

        thread_list_t *current = SLIST_FIRST(&head);
        thread_list_t *temp_var;

        while (current != NULL)
        {
            temp_var = SLIST_NEXT(current, entries);

            int ret = pthread_tryjoin_np(current->thread_id, NULL);
            if (ret == 0)
            {
                SLIST_REMOVE(&head, current, thread_list_s, entries);
                free(current);
            }
            current = temp_var;
        }
    }

    cleanup(0);
}