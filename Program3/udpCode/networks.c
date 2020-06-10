
// Hugh Smith April 2017
// Network code to support TCP/UDP client and server connections

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "networks.h"
#include "gethostbyname.h"
#include "cpe464.h"


int safeRecvfrom(int socketNum, void * buf, int len, int flags, struct sockaddr *srcAddr, int * addrLen)
{
	int returnValue = 0;
	if ((returnValue = recvfrom(socketNum, buf, (size_t) len, flags, srcAddr, (socklen_t *) addrLen)) < 0)
	{
		perror("recvfrom: ");
		exit(-1);
	}
	
	return returnValue;
}

int safeSendto(int socketNum, void * buf, int len, int flags, struct sockaddr *srcAddr, int addrLen)
{
	int returnValue = 0;
	if ((returnValue = sendtoErr(socketNum, buf, (size_t) len, flags, srcAddr, (socklen_t) addrLen)) < 0)
	{
		perror("sendto: ");
		exit(-1);
	}
	
	return returnValue;
}

int safeRecv(int socketNum, void * buf, int len, int flags)
{
	int returnValue = 0;
	if ((returnValue = recv(socketNum, buf, (size_t) len, flags)) < 0)
	{
		perror("recv: ");
		exit(-1);
	}
	
	return returnValue;
}

int safeSend(int socketNum, void * buf, int len, int flags)
{
	int returnValue = 0;
	if ((returnValue = send(socketNum, buf, (size_t) len, flags)) < 0)
	{
		perror("send: ");
		exit(-1);
	}
	
	return returnValue;
}


// This function sets the server socket. The function returns the server
// socket number and prints the port number to the screen.  

int tcpServerSetup(int portNumber)
{
	int server_socket= 0;
	struct sockaddr_in6 server;     
	socklen_t len= sizeof(server);  

	server_socket= socket(AF_INET6, SOCK_STREAM, 0);
	if(server_socket < 0)
	{
		perror("socket call");
		exit(1);
	}

	server.sin6_family= AF_INET6;         		
	server.sin6_addr = in6addr_any;   
	server.sin6_port= htons(portNumber);         

	// bind the name (address) to a port 
	if (bind(server_socket, (struct sockaddr *) &server, sizeof(server)) < 0)
	{
		perror("bind call");
		exit(-1);
	}
	
	// get the port name and print it out
	if (getsockname(server_socket, (struct sockaddr*)&server, &len) < 0)
	{
		perror("getsockname call");
		exit(-1);
	}

	if (listen(server_socket, BACKLOG) < 0)
	{
		perror("listen call");
		exit(-1);
	}
	
	printf("Server Port Number %d \n", ntohs(server.sin6_port));
	
	return server_socket;
}

// This function waits for a client to ask for services.  It returns
// the client socket number.   

int tcpAccept(int server_socket, int debugFlag)
{
	struct sockaddr_in6 clientInfo;   
	int clientInfoSize = sizeof(clientInfo);
	int client_socket= 0;

	if ((client_socket = accept(server_socket, (struct sockaddr*) &clientInfo, (socklen_t *) &clientInfoSize)) < 0)
	{
		perror("accept call");
		exit(-1);
	}
	  
	if (debugFlag)
	{
		printf("Client accepted.  Client IP: %s Client Port Number: %d\n",  
				getIPAddressString6(clientInfo.sin6_addr.s6_addr), ntohs(clientInfo.sin6_port));
	}
	

	return(client_socket);
}

int tcpClientSetup(char * serverName, char * port, int debugFlag)
{
	// This is used by the client to connect to a server using TCP
	
	int socket_num;
	uint8_t * ipAddress = NULL;
	struct sockaddr_in6 server;      
	
	// create the socket
	if ((socket_num = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
	{
		perror("socket call");
		exit(-1);
	}

	// setup the server structure
	server.sin6_family = AF_INET6;
	server.sin6_port = htons(atoi(port));
	
	// get the address of the server 
	if ((ipAddress = gethostbyname6(serverName, &server)) == NULL)
	{
		exit(-1);
	}

	if(connect(socket_num, (struct sockaddr*)&server, sizeof(server)) < 0)
	{
		perror("connect call");
		exit(-1);
	}

	if (debugFlag)
	{
		printf("Connected to %s IP: %s Port Number: %d\n", serverName, getIPAddressString6(ipAddress), atoi(port));
	}
	
	return socket_num;
}

int udpServerSetup(int portNumber)
{
	struct sockaddr_in6 server;
	int socketNum = 0;
	int serverAddrLen = 0;	
	
	// create the socket
	if ((socketNum = socket(AF_INET6,SOCK_DGRAM,0)) < 0)
	{
		perror("socket() call error");
		exit(-1);
	}
	
	// set up the socket
	server.sin6_family = AF_INET6;    		// internet (IPv6 or IPv4) family
	server.sin6_addr = in6addr_any ;  		// use any local IP address
	server.sin6_port = htons(portNumber);   // if 0 = os picks 

	// bind the name (address) to a port
	if (bind(socketNum,(struct sockaddr *) &server, sizeof(server)) < 0)
	{
		perror("bind() call error");
		exit(-1);
	}

	/* Get the port number */
	serverAddrLen = sizeof(server);
	getsockname(socketNum,(struct sockaddr *) &server,  (socklen_t *) &serverAddrLen);
	printf("Server using Port #: %d\n", ntohs(server.sin6_port));

	return socketNum;	
	
}

int setupUdpClientToServer(struct sockaddr_in6 *server, char * hostName, int portNumber)
{
	// currently only setup for IPv4 
	int socketNum = 0;
	char ipString[INET6_ADDRSTRLEN];
	uint8_t * ipAddress = NULL;
	
	// create the socket
	if ((socketNum = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket() call error");
		exit(-1);
	}
  	 	
	if ((ipAddress = gethostbyname6(hostName, server)) == NULL)
	{
		exit(-1);
	}
	
	server->sin6_port = ntohs(portNumber);
	server->sin6_family = AF_INET6;	
	
	inet_ntop(AF_INET6, ipAddress, ipString, sizeof(ipString));
	printf("Server info - IP: %s Port: %d \n", ipString, portNumber);
		
	return socketNum;
}

// Wait function for receiving data
int waitForPacket(int socketNum, int timeout){
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(socketNum, &fds);

	if (select(socketNum + 1, &fds, NULL, NULL, &tv) <= 0){
		return 0;
	}
	return 2;
}

int checkCKSUM(uint8_t *aPDU, int length){
	int result = 0;
	
	if (result = in_cksum((short unsigned *) aPDU, length)){
		if (DEBUG_OFF){
			printBytes(aPDU, length);
			printf("Checksum Error: %u\n", result);
		}
		return 0;
	}
	return 1;
}


struct Packet initPacket(int bufferSize){
	struct Packet packet = (struct Packet){
		.sequenceNumber = 0, 
		.flag = 0,
		.packetLen = 7,
		.payload = (uint8_t *)calloc(bufferSize, sizeof(uint8_t))
		};
	return packet;
}

struct Window *initWindow(int windowSize, int bufferSize){
	struct Packet packet = initPacket(bufferSize + 7);
	struct Window *window = (struct Window *)malloc(sizeof(struct Window));
	int i;

	window->windowSize = windowSize;
	window->closed = 0;
	window->currentIdx = 0; 
	window->lowestIdx = 0;
	window->highestIdx = windowSize;
	window->nextPos = 0;
	window->buffer = (struct Packet*)calloc(windowSize + 1, sizeof(packet));
	
	for (i = 0; i < windowSize + 1; i++){
		window->buffer[i] = initPacket(bufferSize + 7);
	}
	
	return window;
}

int isWindowClosed(struct Window *window){
	if (abs(window->currentIdx - window->highestIdx) == 0){
		window->closed = 1;
	}else{
		window->closed = 0;
	}
	return window->closed;
}

void updateWindowStatus(struct Window *window, int currentIdx, int lowestIdx, int highestIdx, int nextPos){
	window->currentIdx = currentIdx % (window->windowSize + 1);
	window->lowestIdx = lowestIdx % (window->windowSize + 1);
	window->highestIdx = highestIdx % (window->windowSize + 1);
	window->nextPos = nextPos % (window->windowSize + 1);
}

// Adds packet to buffer
void addPacket(struct Window *window, int sequenceNumber, int flag, uint8_t *buffer){
	uint8_t *sendBuf;
	sendBuf = createPDU(sequenceNumber, flag, buffer, strlen(buffer) + 7);
	
	window->buffer[window->nextPos].sequenceNumber = sequenceNumber;
	window->buffer[window->nextPos].flag = flag;
	window->buffer[window->nextPos].packetLen = strlen(buffer) + 7;
	memcpy(window->buffer[window->nextPos].payload, sendBuf, strlen(buffer) + 7);
	updateWindowStatus(window, window->currentIdx, window->lowestIdx, window->highestIdx, window->nextPos + 1);
	
}

// Sent first to connect to server/forked child 
int sendInitPacket(int socketNum, struct sockaddr_in6 *srcAddr, int srcAddrLen){
	uint8_t *sendBuf;
	char *payload = "";
	int flag = 1;
	int bufferLen = 7;
	int sequenceNumber = 0;

	sendBuf = createPDU(sequenceNumber, flag, (uint8_t*) payload, bufferLen);
	safeSendto(socketNum, sendBuf, bufferLen, 0, (struct sockaddr*) srcAddr, srcAddrLen);
	return 1;
}

// Helps send Filename, window size, and buffer size
int sendConnectionPackets(int socketNum, struct sockaddr_in6 *srcAddr, int srcAddrLen, uint8_t *payload, int flag){
	int bufferLen = 7 + strlen(payload);
	uint8_t *sendBuf;

	sendBuf = createPDU(0, flag, payload, bufferLen);
	safeSendto(socketNum, sendBuf, bufferLen, 0, (struct sockaddr *) srcAddr, srcAddrLen);
	return flag + 1;
}

// 4-byte sequence number in network order, 2-byte checksum, 1-byte flag, (remainder of packet)
// Sequence Number: 32 bit sequence number in network order
// flag : the type of the PDU
// payload : Payload (data) of the PDU (may not be nulled terminated)
// dataLen: lenght of the payload (so # of bytes in data)
uint8_t *createPDU(uint32_t sequenceNumber, uint8_t flag, uint8_t *payload, int dataLen){
	static uint8_t pduBuffer[MAXBUF + 1];
	uint16_t checkSum;
	uint32_t netOrdSequenceNumber = htonl(sequenceNumber);
	
	memset(pduBuffer, 0, MAXBUF + 1);
	memcpy(pduBuffer, &netOrdSequenceNumber, 4);
	memcpy(pduBuffer + 6, &flag, 1);
	memcpy(pduBuffer + 7, payload, dataLen - 7);
	checkSum = in_cksum((short unsigned *)pduBuffer, dataLen);
	memcpy(pduBuffer + 4, &checkSum, 2);
	return pduBuffer;
}

// Prints some elements within the PDU
void outputPDU(uint8_t *aPDU, int pduLength){
	uint32_t sequenceNumber;
	uint8_t flag;

	memcpy(&sequenceNumber, aPDU, 4);
	memcpy(&flag, aPDU + 6, 1);
	
	printf("Sequence Number\t- %i\n", htonl(sequenceNumber));
	printf("Flag\t- %i\n", flag);
	printf("Payload Length\t- %i\n", pduLength - 7);
	printf("Payload\t - %s\n", aPDU + 7);
}

void printBytes(uint8_t *PDU, int length){
	int i;
	printf("\tHex\t|\tNum\t|\tChar\n");
	for (i = 0; i < length; i++){
		printf("%i:\t%x\t|\t%i\t|\t%c\n", i, PDU[i] & 0xffff, PDU[i], PDU[i]);
	}
}
