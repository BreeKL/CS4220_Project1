# Makefile for building client and server, generating certificates, and linking OpenSSL & Winsock libraries

# Paths for OpenSSL and WinSock
OPENSSL_DIR = /path/to/openssl
WINSOCK_LIB = -lws2_32

# Source and output files
SERVER_SRC = server.c
SERVER_OUT = server.exe
CLIENT_SRC = client.c
CLIENT_OUT = client.exe

# Certificate and key files
CLIENT_CERT = certs/client.crt
CLIENT_KEY = certs/client.key
SERVER_CERT = certs/server.crt
SERVER_KEY = certs/server.key
CA_CERT = certs/ca.crt  # Assuming you have a CA certificate

# OpenSSL binary (ensure OpenSSL is installed and accessible)
OPENSSL = openssl

# Compiler and flags
CC = gcc
CFLAGS = -Wall
LDFLAGS = -lssl -lcrypto $(WINSOCK_LIB)

# All targets
all: $(SERVER_OUT) $(CLIENT_OUT) $(SERVER_CERT) $(SERVER_KEY) $(CLIENT_CERT) $(CLIENT_KEY)

# Rule to compile server
$(SERVER_OUT): $(SERVER_SRC) $(SERVER_CERT) $(SERVER_KEY)
	$(CC) $(CFLAGS) -o $(SERVER_OUT) $(SERVER_SRC) $(LDFLAGS)

# Rule to compile client
$(CLIENT_OUT): $(CLIENT_SRC) $(CLIENT_CERT) $(CLIENT_KEY)
	$(CC) $(CFLAGS) -o $(CLIENT_OUT) $(CLIENT_SRC) $(LDFLAGS)

# Rule to generate client certificate and key (self-signed)
$(CLIENT_CERT): $(CLIENT_KEY)
	@echo "Generating client certificate..."
	$(OPENSSL) req -new -x509 -days 365 -key $(CLIENT_KEY) -out $(CLIENT_CERT) -subj "/C=US/ST=State/L=City/O=Company/CN=client"

$(CLIENT_KEY):
	@echo "Generating client private key..."
	$(OPENSSL) genpkey -algorithm RSA -out $(CLIENT_KEY)

# Rule to generate server certificate and key (self-signed)
$(SERVER_CERT): $(SERVER_KEY)
	@echo "Generating server certificate..."
	$(OPENSSL) req -new -x509 -days 365 -key $(SERVER_KEY) -out $(SERVER_CERT) -subj "/C=US/ST=State/L=City/O=Company/CN=server"

$(SERVER_KEY):
	@echo "Generating server private key..."
	$(OPENSSL) genpkey -algorithm RSA -out $(SERVER_KEY)

# Clean up generated files
clean:
	rm -f $(SERVER_OUT) $(CLIENT_OUT) $(SERVER_CERT) $(SERVER_KEY) $(CLIENT_CERT) $(CLIENT_KEY)

.PHONY: all clean
