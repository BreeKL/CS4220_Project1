#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define PORT 8080
#define SECRET_KEY "mysecretkey" // Pre-shared key for HMAC

void handle_errors(const char *msg) {
    fprintf(stderr, "%s: %s\n", msg, ERR_error_string(ERR_get_error(), NULL));
    exit(EXIT_FAILURE);
}

void compute_hmac(const char *message, unsigned char *hmac_result, unsigned int *hmac_len) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) handle_errors("Failed to create HMAC context");

    if (!HMAC_Init_ex(ctx, SECRET_KEY, strlen(SECRET_KEY), EVP_sha256(), NULL))
        handle_errors("HMAC Init failed");

    if (!HMAC_Update(ctx, (unsigned char *)message, strlen(message)))
        handle_errors("HMAC Update failed");

    if (!HMAC_Final(ctx, hmac_result, hmac_len))
        handle_errors("HMAC Final failed");

    HMAC_CTX_free(ctx);
}

void communicate(SSL *ssl) {
    char response[] = "Hello from Server";
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;

    // Compute HMAC for the message
    compute_hmac(response, hmac_result, &hmac_len);

    // Read client message
    char buffer[1024];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
    perror("Failed to read message from client");
    exit(1);
    }

    buffer[bytes_received] = '\0'; // Null-terminate received data
    printf("Message from client: %s\n", buffer);

    // Send message
    if (SSL_write(ssl, response, strlen(response)) <= 0) {
        perror("Failed to send response to client");
        exit(1);
    }

    // Send HMAC
    SSL_write(ssl, hmac_result, hmac_len);

    printf("Sent message with HMAC verification\n");
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) handle_errors("Failed to create SSL context");

    if (!SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM))
    handle_errors("Failed to load server certificate");

    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM))
    handle_errors("Failed to load server private key");

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) handle_errors("Socket creation failed");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        handle_errors("Bind failed");

    if (listen(server_fd, 1) == -1) handle_errors("Listen failed");

    printf("Server listening on port %d...\n", PORT);

    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd == -1) handle_errors("Accept failed");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) handle_errors("SSL accept failed");

    printf("Client connected!\n");

    // Communicate with client
    communicate(ssl);

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client_fd);
    closesocket(server_fd);
    SSL_CTX_free(ctx);
    WSACleanup();
}
