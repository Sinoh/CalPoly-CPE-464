/* Server side - UDP Code				    */
/* By Hugh Smith	4/1/2017	*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h> 

#include "gethostbyname.h"
#include "networks.h"
#include "cpe464.h"

int checkArgs(int argc, char *argv[]);
void processClient(int socketNum, int portNumber);
int clientToChild(int socketNum, struct sockaddr_in6 client, int clientAddrLen, int portNumber);
int getInitPackets(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct RuntimeArgs *args);
int checkForFile(char *fileName);
int sendFileStatus(int socketNum, struct sockaddr_in6 client, int clientAddrLen, char *fileName);
int sendFileToClient(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct RuntimeArgs args);
int processResponse(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct Window *window, int bufferSize);
int processResponse2(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct Window *window, int bufferSize);
int sendEOF(int socketNum, struct sockaddr_in6 client, int clientAddrLen, int sequenceNumber);


int main ( int argc, char *argv[]  ){ 
	int socketNum = 0;				
	int portNumber = 0;

	portNumber = checkArgs(argc, argv);
	
	socketNum = udpServerSetup(portNumber);
	sendErr_init(atof(argv[1]), DROP_ON, FLIP_ON, DEBUG_ON, RSEED_OFF);	
	processClient(socketNum, portNumber);
	close(socketNum);
	
	return 0;
}

int checkArgs(int argc, char *argv[]){
	// Checks args and returns port number
	int portNumber = 0;

	if (argc > 3){
		fprintf(stderr, "Usage %s error-percent [optional port number]\n", argv[0]);
		exit(-1);
	}
	
	if (argc == 3){
		portNumber = atoi(argv[2]);
	}
	
	return portNumber;
}

void processClient(int socketNum, int portNumber){
	struct sockaddr_in6 client;	
	struct RuntimeArgs args;
	uint8_t buffer[MAXBUF + 1];
	int clientAddrLen = sizeof(client);	
	int returnVal = 1;
	int dataLen = 0;
	int stat;
	
	while (returnVal > 0){	
		if (waitForPacket(socketNum, NO_TIMEOUT)){
			memset(buffer, 0, MAXBUF + 1);
			dataLen = safeRecvfrom(socketNum, buffer, MAXBUF, 0, (struct sockaddr *) &client, &clientAddrLen);
			if (checkCKSUM(buffer, dataLen)){
				portNumber++;
				if (fork() == 0){
					socketNum = clientToChild(socketNum, client, clientAddrLen, portNumber);
					getInitPackets(socketNum, client, clientAddrLen, &args);
					sendFileStatus(socketNum, client, clientAddrLen, args.fromFileName);
					sendFileToClient(socketNum, client, clientAddrLen, args);
					close(socketNum);
					exit(1);
				}
			}
		}
		waitpid(-1, &stat, WNOHANG);
	}
	exit(1);
}

int clientToChild(int socketNum, struct sockaddr_in6 client, int clientAddrLen, int portNumber){
	uint8_t buffer[MAXBUF + 1];
	uint8_t *sendBuf;
	int counter = 0;
	int dataLen = 0;

	sendBuf = createPDU(DEFAULT_SEQNUM, SETUP_FLAG, (uint8_t*) "", HEADER_LENGTH);
	socketNum = udpServerSetup(portNumber);
	
	while(counter++ < COUNT_LIMIT){
		safeSendto(socketNum, sendBuf, HEADER_LENGTH, 0, (struct sockaddr *) &client, clientAddrLen);
		if (waitForPacket(socketNum, TIMEOUT_1)){
			dataLen = safeRecvfrom(socketNum, buffer, MAXBUF, 0, (struct sockaddr *) &client, &clientAddrLen);
			if (checkCKSUM(buffer, dataLen)){
				return socketNum;
			}
		}
	}
	exit(-1);
}

int getInitPackets(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct RuntimeArgs *args){
	uint8_t buffer[MAXBUF + 1];
	uint8_t *payload = buffer;
	char fileName[MAX_FILENAME_SIZE + 1];
	int dataLen = 0;
	int counter = 0;

	memset(fileName, 0, MAX_FILENAME_SIZE + 1);

	while(counter++ < COUNT_LIMIT){
		if (waitForPacket(socketNum, TIMEOUT_1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, buffer, MAXBUF, 0, (struct sockaddr *) &client, &clientAddrLen);
			if (checkCKSUM(buffer, dataLen)){
				if (buffer[6] == FILENAME_FLAG){
					memcpy(fileName, buffer + HEADER_LENGTH, dataLen - HEADER_LENGTH);
					args->fromFileName = fileName;
					sendConnectionPackets(socketNum, &client, clientAddrLen, payload, FILENAME_ACK_FLAG);
				}else if (buffer[6] == WINDOW_FLAG){
					memcpy(&args->windowSize, buffer + HEADER_LENGTH, 4);
					sendConnectionPackets(socketNum, &client, clientAddrLen, payload, WINDOW_ACK_FLAG);
				}else if (buffer[6] == BUFFER_FLAG){
					memcpy(&args->bufferSize, buffer + HEADER_LENGTH, 4);
					sendConnectionPackets(socketNum, &client, clientAddrLen, payload, BUFFER_ACK_FLAG);
					return 1;
				}else{ 
					continue;
			 	}
			}
		}
	}
	exit(-1);
}

int sendFileNameACK(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct RuntimeArgs *args){
	uint8_t buffer[MAXBUF + 1];
	uint8_t *payload = buffer;
	char fileName[MAX_FILENAME_SIZE + 1];
	int dataLen = 0;
	int counter = 0;

	while(counter++ < COUNT_LIMIT){
		if (waitForPacket(socketNum, TIMEOUT_1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, buffer, MAXBUF, 0, (struct sockaddr *) &client, &clientAddrLen);
			if (checkCKSUM(buffer, dataLen)){
				if (buffer[6] == FILENAME_FLAG){
					memcpy(fileName, buffer + HEADER_LENGTH, dataLen - HEADER_LENGTH);
					args->fromFileName = fileName;
					sendConnectionPackets(socketNum, &client, clientAddrLen, payload, RR_FLAG);
				}

				if (buffer[6] == WINDOW_FLAG){
					return 1;
				}
			}
		}
	}
	exit(-1);
}


int sendFileStatus(int socketNum, struct sockaddr_in6 client, int clientAddrLen, char *fileName){
	uint8_t *sendBuf;

	if (checkForFile(fileName)){
		// Send Ack error
		sendBuf = createPDU(DEFAULT_SEQNUM, FILE_STATUS_REJ_FLAG, (uint8_t*) "", HEADER_LENGTH);
		safeSendto(socketNum, sendBuf, HEADER_LENGTH, 0, (struct sockaddr *) &client, clientAddrLen);
		exit(-1);
	}else{
		//Ack
		sendBuf = createPDU(DEFAULT_SEQNUM, FILE_STATUS_FLAG, (uint8_t*) "", HEADER_LENGTH);
		safeSendto(socketNum, sendBuf, 7, 0, (struct sockaddr *) &client, clientAddrLen);
		return 1;
	}		
}

int checkForFile(char *fileName){
	struct dirent *de;
	DIR *dr = opendir("."); 
	
	if (dr != NULL){
		while ((de = readdir(dr)) != NULL) {
			if (strcmp(fileName, de->d_name) == 0){
				return 0;
			}
		}
	}

	return 1;
}

//Too Long, Need to break up
int sendFileToClient(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct RuntimeArgs args){
	FILE *fp;
	struct Window *window = initWindow(args.windowSize, args.bufferSize);
	char buffer[args.bufferSize + 1];
	int eof = 1;
	int counter = 0;
	int sequenceNumber = 0;
	int lastNumber = 0;
	int RR = 0;
	
	fp = fopen(args.fromFileName, "r");
	if (fp == NULL){
		printf("File could not be open");
		exit(-1);
	}

	while(eof){
		if (window->nextPos != window->highestIdx){
			if (fgets(buffer, args.bufferSize + 1, fp) != NULL){
				addPacket(window, sequenceNumber++, DATA_FLAG, (uint8_t *) buffer);
				lastNumber = sequenceNumber;
			}else{ break; }
		}
		if (!isWindowClosed(window)){
			safeSendto(socketNum, window->buffer[window->currentIdx].payload, window->buffer[window->currentIdx].packetLen, 
				0, (struct sockaddr *) &client, clientAddrLen);
			updateWindowStatus(window, window->currentIdx + 1, window->lowestIdx, window->highestIdx, window->nextPos);

			if(waitForPacket(socketNum, NO_TIMEOUT)){
				RR = processResponse(socketNum, client, clientAddrLen, window, args.bufferSize);
				counter = 0;
			}
		}else{
			if(waitForPacket(socketNum, TIMEOUT_1)){
				RR = processResponse(socketNum, client, clientAddrLen, window, args.bufferSize);
				counter = 0;
			}else{
				if(counter++ < COUNT_LIMIT){
					safeSendto(socketNum, window->buffer[window->lowestIdx].payload, window->buffer[window->lowestIdx].packetLen, 
						0, (struct sockaddr *) &client, clientAddrLen);
				}else{ eof = 0; }
			}
		}
	}

	
	while(RR < lastNumber){
		if(waitForPacket(socketNum, TIMEOUT_1)){
			RR = processResponse2(socketNum, client, clientAddrLen, window, args.bufferSize);
			safeSendto(socketNum, window->buffer[window->lowestIdx].payload, window->buffer[window->lowestIdx].packetLen, 
				0, (struct sockaddr *) &client, clientAddrLen);;
			counter = 0;	
		}else{
			safeSendto(socketNum, window->buffer[window->lowestIdx].payload, window->buffer[window->lowestIdx].packetLen, 
				0, (struct sockaddr *) &client, clientAddrLen);
			if(counter++ > COUNT_LIMIT){ break; }
		}
	}

	sendEOF(socketNum, client, clientAddrLen, sequenceNumber);
	fclose(fp);
	return 0;
}

int processResponse(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct Window *window, int bufferSize){
	uint32_t recvRR;
	char buffer[bufferSize + 1];
	int dataLen = 0;
	int newRR;

	
	dataLen = safeRecvfrom(socketNum, buffer, HEADER_LENGTH + 4, 0, (struct sockaddr *) &client, &clientAddrLen);
	if (!checkCKSUM((uint8_t *) buffer, dataLen)){
		return 0;
	}else{
		if (buffer[6] == RR_FLAG){
			memcpy(&recvRR, buffer + HEADER_LENGTH, 4);
			recvRR = ntohl(recvRR);
			newRR = recvRR - window->buffer[window->lowestIdx].sequenceNumber;
			updateWindowStatus(window, window->currentIdx, window->lowestIdx + newRR, window->highestIdx + newRR, window->nextPos);
			
		}else if(buffer[6] == SREJ_FLAG){
			memcpy(&recvRR, buffer + HEADER_LENGTH, 4);
			recvRR = ntohl(recvRR);
			newRR = recvRR - window->buffer[window->lowestIdx].sequenceNumber;
			updateWindowStatus(window, window->lowestIdx + newRR, window->lowestIdx + newRR, window->highestIdx + newRR, window->nextPos);
		}
	}
	return recvRR;
}

int processResponse2(int socketNum, struct sockaddr_in6 client, int clientAddrLen, struct Window *window, int bufferSize){
	char buffer[bufferSize + 1];
	uint32_t recvRR;
	int dataLen = 0;
	int newRR;

	dataLen = safeRecvfrom(socketNum, buffer, MAXBUF, 0, (struct sockaddr *) &client, &clientAddrLen);
	if (!checkCKSUM((uint8_t *)buffer, dataLen)){
		return 0;
	}else{
		memcpy(&recvRR, buffer + HEADER_LENGTH, 4);
		recvRR = ntohl(recvRR);
		newRR = recvRR - window->buffer[window->lowestIdx].sequenceNumber;
		if (buffer[6] == RR_FLAG){
			updateWindowStatus(window, window->currentIdx, window->lowestIdx + newRR, window->highestIdx, window->nextPos);
		}else if(buffer[6] == SREJ_FLAG){
			updateWindowStatus(window, window->lowestIdx + newRR, window->lowestIdx + newRR, window->highestIdx, window->nextPos);
		}
	}
	return recvRR;
}

int sendEOF(int socketNum, struct sockaddr_in6 client, int clientAddrLen, int sequenceNumber){
	uint8_t buffer[HEADER_LENGTH + 4];
	uint8_t *sendBuf;
	int counter = 0;
	int dataLen = 0;

	sendBuf = createPDU(sequenceNumber++, EOF_FLAG, (uint8_t *) "", HEADER_LENGTH);
	while (counter++ < COUNT_LIMIT){
		dataLen = safeSendto(socketNum, sendBuf, HEADER_LENGTH, 0, (struct sockaddr *) &client, clientAddrLen);
		if(waitForPacket(socketNum, TIMEOUT_1)){
			safeRecvfrom(socketNum, buffer, MAXBUF, 0, (struct sockaddr *) &client, &clientAddrLen);
			if (checkCKSUM(buffer, dataLen)){
				if (buffer[6] == EOF_ACK_FLAG){
					return 1;
				}
			}
		}
	}
	return 1;
}

