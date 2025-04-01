CS4220 Computer Networks
Project 1

Brianne Leatherman
Samuel Karlin


DISCLAIMER: 
===========
We have neither given nor received unauthorized assistance on this work.


PROGRAM DESCRIPTION:
====================
This program uses OpenSSL to establish a mutual authentication TLS 
connection between a server and a client, securing communication with 
TLS_AES_256_GCM_SHA384 encryption and utilizing HMAC-SHA256 to verify 
message integrity.


FILE DESCRIPTIONS:
==================
compNetworks directory: contains the following program files

    client.c: establishes a TLS/SSL connection with the server after passing 
	certificate and key verifications, sends a message to the server 
	along with an HMAC for integrity verification, then waits for the 
	server’s response before ending communication and closing connection

    server.c: creates a socket to listen for incoming client connections, 
	establishes a TLS handshake after verifying the client's certificate, 
	then begins secure communication, ensuring message integrity using HMAC

    certs directory: contains the keys and certificates generated for 
	the client and server

    Makefile: creates client/server certificates and keys and places them
	in the certs directory, and compiles the .c files into executables

README: contains descriptions and instructions


BUILD AND RUN INSTRUCTIONS:
===========================
This project will run in the Blanca/Redcloud server. Code is also available
on GitHub from https://github.com/BreeKL/CS4220_Project1. 

* Open two terminal windows and open the compNetworks directory in both. 
* Build the program with the make command. 
* Start the program server by running ./server in one terminal, 
  and then run the client with ./client in the second termial. 

	Expected output from server:
	
	Server listening on port 8080...
	Client connected!
	Message from client: Hello, Server!
	Sent message with HMAC verification
	Connection closed
	
	Expected output from client:
	
	Connected with TLS_AES_256_GCM_SHA384 encryption
	Message sent to server: Hello, Server!
	HMAC sent to server
	Server response: Hello from Server
	Closing connection to server


CHALLENGES/RESOURCES:
=====================
This code was originally developed in a Windows environment and initially would 
not run on a Linux machine. When working in Windows, the OpenSSL sockets need to
be created using the winsock2 library; however, Linux creates them differently
using the sys/socket library. Thankfully, sockets could be treated similarly once 
created. https://beej.us/guide/bgnet/html/split/intro.html#windows was essential
in figuring out the necessary changes to switch between the two. Additionally, 
the Makefile needed to be changed to create different executable files. 
Windows needs .exe files, while Linux uses .o files, which was a relatively
simple fix.

Otherwise, the resources provided in the project instructions were very 
descriptive and creating the certificates, sockets, TLS handshake, and
communication between the client and server was fairly straightforward. 
We found the O'Reilly textbook "Demystifying Cryptography with OpenSSL" 
and Baeldung's "Creating a Self-Signed Certificate With OpenSSL" to be 
the most helpful, since they included code snippets to show how things 
worked. Also, the Stanford CS library was helpful to find C functions, and 
https://knowledge.digicert.com/general-information/openssl-quick-reference-guide
helped with using OpenSSL to create the certificates. 


