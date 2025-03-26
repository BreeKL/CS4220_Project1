#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#pragma comment(lib, "ws2_32.lib") // Link with Winsock library

#define SERVER_HOST "127.0.0.1"  // Server's IP address or hostname
#define SERVER_PORT 8080         // Server's port

// Function to handle errors
void handle_errors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Function to initialize OpenSSL library
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to cleanup OpenSSL resources
void cleanup_openssl(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

// HMAC function to ensure data integrity
void hmac_sha256(const unsigned char *data, size_t data_len, const unsigned char *key, size_t key_len, unsigned char *out) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        handle_errors("Failed to create HMAC context");
    }

    if (HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL) != 1) {
        handle_errors("HMAC initialization failed");
    }

    if (HMAC_Update(ctx, data, data_len) != 1) {
        handle_errors("HMAC update failed");
    }

    unsigned int len;
    if (HMAC_Final(ctx, out, &len) != 1) {
        handle_errors("HMAC finalization failed");
    }

    HMAC_CTX_free(ctx);
}

// Main client function
int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[1024];

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        handle_errors("WSAStartup failed");
    }

    // Initialize OpenSSL
    init_openssl();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        handle_errors("Unable to create SSL context");
    }

    // Load client certificate
    if (!SSL_CTX_use_certificate_file(ctx, "certs/client.crt", SSL_FILETYPE_PEM)) {
        handle_errors("Failed to load client certificate");
    }

    // Load client private key
    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client.key", SSL_FILETYPE_PEM)) {
        handle_errors("Failed to load client private key");
    }

    // Verify client private key
    if (!SSL_CTX_check_private_key(ctx)) {
        handle_errors("Client private key does not match the certificate public key");
    }

    // Load server certificate as CA certificate for validation
    if (!SSL_CTX_load_verify_locations(ctx, "certs/server.crt", NULL)) {
        handle_errors("Failed to load CA certificate");
    }

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        handle_errors("Unable to create socket");
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_HOST);

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        handle_errors("Unable to connect to server");
    }

    // Create SSL structure and connect it to the socket
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_errors("Unable to create SSL structure");
    }

    SSL_set_fd(ssl, sock);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        handle_errors("SSL handshake failed");
    }

    // Print the connection details
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

    // Send a message to the server
    const char *message = "Hello, Server!";
    if (SSL_write(ssl, message, strlen(message)) <= 0) {
        handle_errors("Failed to send message");
    }
    printf("Message sent to server: %s\n", message);

    // Create HMAC for data integrity
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    unsigned char secret_key[] = "my_secret_key";  // Use a fixed secret key for HMAC
    hmac_sha256((unsigned char *)message, strlen(message), secret_key, sizeof(secret_key) - 1, hmac_result);

    // Send HMAC to the server
    if (SSL_write(ssl, hmac_result, SHA256_DIGEST_LENGTH) <= 0) {
        handle_errors("Failed to send HMAC");
    }
    printf("HMAC sent to server\n");

    // Read the server's response
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
if (bytes_received <= 0) {
    perror("Failed to read response from server");
    exit(1);
}

buffer[bytes_received] = '\0'; // Null-terminate the response
printf("Server response: %s\n", buffer);

    // Cleanup
    SSL_shutdown(ssl);
    closesocket(sock);
    cleanup_openssl(ctx);
    WSACleanup();

    return 0;
}
