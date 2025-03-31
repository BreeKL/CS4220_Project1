CS4220 Computer Networks
Project 1

Brianne Leatherman
Samuel Karlin



DISCLAIMER: 
===========
We have neither given nor received unauthorized assistance on this work.

PROGRAM DESCRIPTION:
====================
This program was created to provide a secure connection with encrypted
communication between a server and a client


FILE DESCRIPTIONS:
==================
compNetworks directory: contains the following program files

    client.c: 

    server.c: 

    certs directory: contains the keys and certificates generated for 
	the client and server

    Makefile: creates client/server certificates and keys and places them
	in the certs directory, and compiles the .c files into executables

README: contains descriptions and instructions


BUILD AND RUN INSTRUCTIONS:
===========================
This project will run in the Blanca/Redcloud server. Code is also available
on GitHub from https://github.com/BreeKL/CS4220_Project1. Open two terminal
windows and open the compNetworks directory in both. Build the program
with the make command. Start the program server by running ./server in 
one terminal, and then run the client with ./client in the second termial. 


CHALLENGES/DISCUSSION:
======================
This code was originally developed in a Windows environment and would not 
run on a Linux machine. When working in Windows, the OpenSSL sockets were 
created using the winsock2 library; however, Linux creates them differently
using the sys/socket library. Sockets could be treated similarly once 
created. Additionally, the Makefile needed to be changed to create different
executable files. Windows needs .exe files, while Linux uses .o files. 


RESOURCES USED:
===============
There were several resources that were used to help guide us through the
project, below is a list of the ones used.
http://cslibrary.stanford.edu/
https://www.oreilly.com/library/view/demystifying-cryptography-with/9781800560345/B16767_10_Final_AM.xhtml#_idParaDest-198%20%C2%A0
https://knowledge.digicert.com/general-information/openssl-quick-reference-guide
These resources helped to complete the project and guide us through
the process of writing the code. The clibrary helped to learn about commands 
that we weren't already familiar with and how to integrate them into the 
project. The oreilly library on cryptography helped with understanding 
TLS and how to implement the TLS handshake, and the openssl reference guide 
showed the commands that we needed and how to use them properly.

