# Makefile for building client and server, generating certificates, and linking OpenSSL on Linux

# Source and output files
SERVER_SRC = server.c
SERVER_OUT = server
CLIENT_SRC = client.c
CLIENT_OUT = client

# Certificate and key files
CA_KEY = certs/ca.key
CA_CERT = certs/ca.crt
SERVER_KEY = certs/server.key
SERVER_CSR = certs/server.csr
SERVER_CERT = certs/server.crt
CLIENT_KEY = certs/client.key
CLIENT_CSR = certs/client.csr
CLIENT_CERT = certs/client.crt

# OpenSSL binary (ensure OpenSSL is installed and accessible)
OPENSSL = openssl

# Compiler and flags
CC = gcc
CFLAGS = -Wall
LDFLAGS = -lssl -lcrypto

# All targets
all: $(SERVER_OUT) $(CLIENT_OUT) $(CA_CERT) $(SERVER_CERT) $(CLIENT_CERT)

# Rule to compile server
$(SERVER_OUT): $(SERVER_SRC) $(SERVER_CERT) $(SERVER_KEY)
	$(CC) $(CFLAGS) -o $(SERVER_OUT) $(SERVER_SRC) $(LDFLAGS)

# Rule to compile client
$(CLIENT_OUT): $(CLIENT_SRC) $(CLIENT_CERT) $(CLIENT_KEY)
	$(CC) $(CFLAGS) -o $(CLIENT_OUT) $(CLIENT_SRC) $(LDFLAGS)

# CA Certificate Generation
$(CA_KEY): certs/
	@echo "Generating CA private key..."
	$(OPENSSL) genpkey -algorithm RSA -out $(CA_KEY)

$(CA_CERT): $(CA_KEY)
	@echo "Generating self-signed CA certificate..."
	$(OPENSSL) req -new -x509 -days 365 -key $(CA_KEY) -out $(CA_CERT) -subj "/C=US/ST=State/L=City/O=Company/CN=MyCustomCA"

# Client Certificate Generation (Signed by CA)
$(CLIENT_KEY): certs/
	@echo "Generating client private key..."
	$(OPENSSL) genpkey -algorithm RSA -out $(CLIENT_KEY)

$(CLIENT_CSR): $(CLIENT_KEY)
	@echo "Generating client CSR..."
	$(OPENSSL) req -new -key $(CLIENT_KEY) -out $(CLIENT_CSR) -subj "/C=US/ST=State/L=City/O=Company/CN=client"

$(CLIENT_CERT): $(CLIENT_CSR) $(CA_CERT)
	@echo "Signing client certificate with CA..."
	$(OPENSSL) x509 -req -in $(CLIENT_CSR) -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(CLIENT_CERT) -days 365

# Server Certificate Generation (Signed by CA)
$(SERVER_KEY): certs/
	@echo "Generating server private key..."
	$(OPENSSL) genpkey -algorithm RSA -out $(SERVER_KEY)

$(SERVER_CSR): $(SERVER_KEY)
	@echo "Generating server CSR..."
	$(OPENSSL) req -new -key $(SERVER_KEY) -out $(SERVER_CSR) -subj "/C=US/ST=State/L=City/O=Company/CN=server"

$(SERVER_CERT): $(SERVER_CSR) $(CA_CERT)
	@echo "Signing server certificate with CA..."
	$(OPENSSL) x509 -req -in $(SERVER_CSR) -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out $(SERVER_CERT) -days 365

# Clean up generated files
clean:
	rm -f $(SERVER_OUT) $(CLIENT_OUT) $(SERVER_CERT) $(SERVER_CSR) $(SERVER_KEY) $(CLIENT_CERT) $(CLIENT_CSR) $(CLIENT_KEY) $(CA_CERT) $(CA_KEY) certs/ca.srl

.PHONY: all clean

