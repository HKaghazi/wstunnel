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

SSL_CTX *create_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main(int argc, char const *argv[]) {
    int opt = TRUE;
    int server_socket, client_socket, activity, valread, sd, max_sd;
    struct sockaddr_in server_address, client_address;
    char buffer[BUFFER_SIZE];
    fd_set readfds;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    SSL_CTX *ctx = create_context();

    // Set level of security
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(SERVER_PORT);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is up, IP address: %s, Port: %d.\n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));

    if (listen(server_socket, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    socklen_t addrlen = sizeof(client_address);
    puts("Waiting for connection ...");

    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    printf("Client connected, IP address: %s, Port: %d.\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

    // Create SSL structure
    SSL *client_ssl = SSL_new(ctx);
    SSL_set_fd(client_ssl, client_socket);

    // Establish SSL connection with client
    int ssl_status = SSL_accept(client_ssl);
    if (ssl_status <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(CLIENT_PORT);

    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    addrlen = sizeof(client_address);
    puts("Waiting for connection ...");

    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    printf("Server connected, IP address: %s, Port: %d.\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

    // Create SSL structure
    SSL *server_ssl = SSL_new(ctx);
    SSL_set_fd(server_ssl, client_socket);

    // Establish SSL connection with server
    ssl_status = SSL_connect(server_ssl);
    if (ssl_status <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    while (TRUE) {
        FD_ZERO(&readfds);
        FD_SET(SSL_get_fd(client_ssl), &readfds);
        FD_SET(SSL_get_fd(server_ssl), &readfds);
        max_sd = (SSL_get_fd(client_ssl) > SSL_get_fd(server_ssl)) ? SSL_get_fd(client_ssl) : SSL_get_fd(server_ssl);

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            printf("select error");
        } else if (activity == 0) { // Timeout occurred
            printf("Timeout occurred. No new data received.\n");
            continue;
        }

        if (FD_ISSET(SSL_get_fd(client_ssl), &readfds)) {
            valread = SSL_read(client_ssl, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                printf("Client disconnected.\n");
                close(client_socket);
                SSL_shutdown(client_ssl);
                SSL_free(client_ssl);
                SSL_CTX_free(ctx);
                return 0;
            }
            buffer[valread] = '\0';
            if (SSL_write(server_ssl, buffer, strlen(buffer)) != strlen(buffer)) {
                perror("send to server failed");
                return -1;
            }
        }

        if (FD_ISSET(SSL_get_fd(server_ssl), &readfds)) {
            valread = SSL_read(server_ssl, buffer, BUFFER_SIZE);
            if (valread <= 0) {
                printf("Server disconnected.\n");
                close(server_socket);
                SSL_shutdown(server_ssl);
                SSL_free(server_ssl);
                SSL_CTX_free(ctx);
                return 0;
            }
            buffer[valread] = '\0';
            if (SSL_write(client_ssl, buffer, strlen(buffer)) != strlen(buffer)) {
                perror("send to client failed");
                return -1;
            }
        }
    }

    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(ctx);

    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(ctx);

    return 0;
}
