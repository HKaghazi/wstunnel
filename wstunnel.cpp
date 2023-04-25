#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define TRUE 1
#define FALSE 0
#define SERVER_PORT 8080
#define CLIENT_PORT 9090
#define BUFFER_SIZE 2048

SSL_CTX *create_context(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int setup_server_socket(int port)
{
    int opt = TRUE;
    int server_socket;
    struct sockaddr_in server_address;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is up, IP address: %s, Port: %d.\n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));

    if (listen(server_socket, 1) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return server_socket;
}

int setup_client_socket(char *ip_address, int port)
{
    int client_socket;
    struct sockaddr_in client_address;

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    client_address.sin_family = AF_INET;
    client_address.sin_addr.s_addr = inet_addr(ip_address);
    client_address.sin_port = htons(port);

    if (connect(client_socket, (struct sockaddr *)&client_address, sizeof(client_address)) < 0)
    {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected, IP address: %s, Port: %d.\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

    return client_socket;
}

SSL *create_ssl_context(SSL_CTX *ctx, int socket_fd)
{
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket_fd);

    // Establish SSL connection with client or server
    int ssl_status = SSL_accept(ssl);
    if (ssl_status <= 0)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ssl;
}

void communicate_over_ssl(SSL *ssl_1, SSL *ssl_2)
{
    int activity, valread, max_sd;
    char buffer[BUFFER_SIZE];
    fd_set readfds;

    while (TRUE)
    {
        FD_ZERO(&readfds);
        FD_SET(SSL_get_fd(ssl_1), &readfds);
        FD_SET(SSL_get_fd(ssl_2), &readfds);
        max_sd = (SSL_get_fd(ssl_1) > SSL_get_fd(ssl_2)) ? SSL_get_fd(ssl_1) : SSL_get_fd(ssl_2);

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR))
        {
            printf("select error");
        }
        else if (activity == 0)
        { // Timeout occurred
            printf("Timeout occurred. No new data received.\n");
            continue;
        }

        if (FD_ISSET(SSL_get_fd(ssl_1), &readfds))
        {
            valread = SSL_read(ssl_1, buffer, BUFFER_SIZE);
            if (valread <= 0)
            {
                printf("Client disconnected.\n");
                close(SSL_get_fd(ssl_1));
                SSL_shutdown(ssl_1);
                SSL_free(ssl_1);
                return;
            }
            buffer[valread] = '\0';
            if (SSL_write(ssl_2, buffer, strlen(buffer)) != strlen(buffer))
            {
                perror("send to server failed");
                return;
            }
        }

        if (FD_ISSET(SSL_get_fd(ssl_2), &readfds))
        {
            valread = SSL_read(ssl_2, buffer, BUFFER_SIZE);
            if (valread <= 0)
            {
                printf("Server disconnected.\n");
                close(SSL_get_fd(ssl_2));
                SSL_shutdown(ssl_2);
                SSL_free(ssl_2);
                return;
            }
            buffer[valread] = '\0';
            if (SSL_write(ssl_1, buffer, strlen(buffer)) != strlen(buffer))
            {
                perror("send to client failed");
                return;
            }
        }
    }

    SSL_shutdown(ssl_1);
    SSL_free(ssl_1);

    SSL_shutdown(ssl_2);
    SSL_free(ssl_2);
}

int main(int argc, char const *argv[])
{
    int server_socket, client_socket;
    SSL_CTX *ctx;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    ctx = create_context();

    // Set level of security
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    server_socket = setup_server_socket(SERVER_PORT);
    printf("Waiting for connection from client...\n");

    printf("NOK NOK\n");

    if ((client_socket = accept(server_socket, (struct sockaddr *)NULL, NULL)) < 0)
    {

        perror("accept");
        exit(EXIT_FAILURE);
    }

    printf("OKOKOKOK\n");

    SSL *server_ssl = create_ssl_context(ctx, client_socket);

    client_socket = setup_client_socket("192.168.1.109", CLIENT_PORT);

    SSL *client_ssl = create_ssl_context(ctx, client_socket);

    communicate_over_ssl(server_ssl, client_ssl);

    SSL_CTX_free(ctx);

    return 0;
}
