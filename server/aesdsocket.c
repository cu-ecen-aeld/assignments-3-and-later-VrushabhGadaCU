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

pthread_t timer_thread_id;
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define DATA_FILE "/var/tmp/aesdsocketdata"
int waiting_for_connection = 0;
#include <signal.h>
int sockfd = -1;
int new_fd = -1;
int fd = -1;

struct addrinfo *servinfo;
volatile sig_atomic_t exit_flag = 0;
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

void *timestamp_thread(void *arg)
{
    (void)arg;
    while (!exit_flag)
    {
        sleep(10);
        

        time_t now;
        struct tm *timeinfo;
        char timestamp[200];

        time(&now);
        timeinfo = localtime(&now);

        strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", timeinfo);

        pthread_mutex_lock(&mutex_lock);
        
        fd = open(DATA_FILE, O_WRONLY | O_APPEND | O_CREAT, 0664);
		if (fd == -1){
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

void clenanup(int return_code)
{
    if (fd != -1)
        close(fd);
    if (new_fd != -1)
        close(new_fd);
    if (sockfd != -1)
        close(sockfd);
    if (servinfo)
        freeaddrinfo(servinfo);

    printf("Joining timer thread\n");

    pthread_join(timer_thread_id, NULL);
    thread_list_t *current = SLIST_FIRST(&head);

    while (current != NULL)
    {
        thread_list_t *next = SLIST_NEXT(current, entries);
        int ret = pthread_join(current->thread_id, NULL);
        if (ret == 0)
        {
            SLIST_REMOVE(&head, current, thread_list_s, entries);
            free(current);
        }
        current = next;
    }

    remove(DATA_FILE);
    exit(return_code); // Changed from exit(0) to exit(return_code)
}

void signal_handler(int sig)
{
    syslog(LOG_INFO, "Caught signal, exiting");
    exit_flag = 1;

    // clenanup(0);
}

void *handle_client(void *arg)
{
    thread_list_t *thread_data = (thread_list_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_received = 0;
    int send_enable = 0;
    while (((bytes_received = recv(thread_data->client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) && (!exit_flag))
    {
        if (buffer[bytes_received - 1] == '\n')
            send_enable = 1;

        pthread_mutex_lock(&mutex_lock);
        fd = open(DATA_FILE, O_WRONLY | O_APPEND | O_CREAT, 0664);
        if (fd == -1)
        {

            syslog(LOG_ERR, "Error opening file %s: %s", DATA_FILE, strerror(errno));
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

        if (!send_enable)
            continue;
        else
        {
            int read_byte = 0;
            int read_fd = open(DATA_FILE, O_RDONLY);
            char send_buf[BUFFER_SIZE];
            if (read_fd == -1)
            {
                perror("open");
                syslog(LOG_ERR, "open");
                return NULL;
            }

            while ((read_byte = read(read_fd, send_buf, sizeof(send_buf))) > 0)
            {
                if (read_byte == -1)
                {
                    perror("read");
                    syslog(LOG_ERR, "read");
                    return NULL;
                }

                read_byte = send(thread_data->client_fd, send_buf, read_byte, 0);
                if (read_byte == -1)
                {
                    perror("send");
                    syslog(LOG_ERR, "send");
                    return NULL;
                }
            }
            close(read_fd);
            send_enable = 0;
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
    SLIST_INIT(&head);

    fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0664);

    if (fd == -1)
    {
        syslog(LOG_ERR, "Failed to open %s: %s", DATA_FILE, strerror(errno));
        clenanup(-1);
    }

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

    if (listen(sockfd, MAX_CLIENTS) < 0)
    {
        perror("Listen failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Start the timestamp thread HERE (after daemon fork, before accept loop)
    if (pthread_create(&timer_thread_id, NULL, timestamp_thread, NULL) != 0)
    {
        syslog(LOG_ERR, "Failed to create timestamp thread");
        clenanup(-1);
    }

    socklen_t addr_size;
    struct sockaddr_storage their_addr;
    addr_size = sizeof their_addr;
    char client_ip[INET6_ADDRSTRLEN];

    while (!exit_flag)
    {
        int client_socket = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if (client_socket < 0)
        {
            perror("Accept failed");
            continue;
        }

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

        if (pthread_create(&thread_node->thread_id, NULL, handle_client, thread_node) != 0)
        {
            perror("Thread creation failed");
            close(client_socket);
            continue;
        }
        SLIST_INSERT_HEAD(&head, thread_node, entries);

        thread_list_t *current = SLIST_FIRST(&head);

        while (current != NULL)
        {
            thread_list_t *next = SLIST_NEXT(current, entries);
            int ret = pthread_tryjoin_np(current->thread_id, NULL);
            if (ret == 0)
            {
                SLIST_REMOVE(&head, current, thread_list_s, entries);
                free(current);
            }
            current = next;
        }
    }
    clenanup(0);
    return 0;
}