// Client side - UDP Code				    
// By Hugh Smith	4/1/2017		

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
#include <ctype.h>

#include "gethostbyname.h"
#include "networks.h"
#include "cpe464.h"

#define DEBUG 0
#define xstr(a) str(a)
#define str(a) #a

int receiveDataPackets(int socketNum, struct sockaddr_in6 *server, int serverAddrLen, struct RuntimeArgs args, FILE *fp);
void talkToServer(int socketNum, struct sockaddr_in6 * server, struct RuntimeArgs args);
int waitForFileStatus(int socketNum, struct sockaddr_in6 *server, char *fileName);
int processDataPacket(uint8_t *recvBuf, int dataLen, FILE *fp, struct Window window, int expectedNumber);
int processBuffer(FILE *fp, struct Window *window, int expectedNumber);
void storePacketInfo(uint8_t *recvBuf, int dataLen, struct Window *window);
void sendACK(int socketNum, struct sockaddr_in6 *server, int serverAddrLen, int sequenceNumber, int payload, int flag);
int initConnection(int socketNum, struct sockaddr_in6 * server, struct RuntimeArgs args);
int sendInitInfo(int socketNum, struct sockaddr_in6 *server, struct RuntimeArgs args);
int sendFileName(int socketNum, struct sockaddr_in6 *server, char *FileName);
int sendWindowSize(int socketNum, struct sockaddr_in6 *server, int windowSize);
int sendBufferSize(int socketNum, struct sockaddr_in6 *server, int bufferSize);

FILE *openOutput(char *outputName);
struct RuntimeArgs checkArgs(int argc, char * argv[]);

void checkFileName(char *filename);
void checkWindowSize(int windowSize);
void checkBufferSize(int bufferSize);
void checkErrorRate(double errorRate);

int main (int argc, char *argv[]){
	struct sockaddr_in6 server;		// Supports 4 and 6 but requires IPv6 struct
	struct RuntimeArgs args;
	int socketNum = 0;				

	args = checkArgs(argc, argv);
	socketNum = setupUdpClientToServer(&server, args.remoteMachine, args.remotePort);
	sendErr_init(args.errorPercent, DROP_ON, FLIP_ON, DEBUG_ON, RSEED_OFF);
	talkToServer(socketNum, &server, args);
	close(socketNum);
	return 0;
}

void talkToServer(int socketNum, struct sockaddr_in6 * server, struct RuntimeArgs args){
	FILE *fp;
	int serverAddrLen = sizeof(struct sockaddr_in6);

	initConnection(socketNum, server, args);
	sendInitInfo(socketNum, server, args);
	waitForFileStatus(socketNum, server, args.fromFileName);
	fp = openOutput(args.toFileName);
	receiveDataPackets(socketNum, server, serverAddrLen, args, fp);
	fclose(fp);
}

int initConnection(int socketNum, struct sockaddr_in6 * server, struct RuntimeArgs args){
	int serverAddrLen = sizeof(struct sockaddr_in6);
	uint8_t recvBuf[MAXBUF + 1];
	int counter = 0;
	int dataLen = 0;
	uint8_t *sendBuf;

	while(counter++ < COUNT_LIMIT){		
		sendInitPacket(socketNum, server, serverAddrLen);		
		if (waitForPacket(socketNum, TIMEOUT_1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, recvBuf, MAXBUF, 0, (struct sockaddr *) server, &serverAddrLen);
			if (checkCKSUM(recvBuf, dataLen)){
				sendBuf = createPDU(DEFAULT_SEQNUM, SETUP_FLAG, (uint8_t*) "", 7);
				safeSendto(socketNum, sendBuf, HEADER_LENGTH, 0, (struct sockaddr*) server, serverAddrLen);
				return 1;
			}
		}
	}

	exit(-1);
}

int sendInitInfo(int socketNum, struct sockaddr_in6 *server, struct RuntimeArgs args){
	int serverAddrLen = sizeof(struct sockaddr_in6);
	uint8_t recvBuf[MAXBUF + 1];
	int counter = 0;
	int dataLen = 0;
	uint8_t *sendBuf;
	uint8_t payload[MAX_FILENAME_SIZE + 1];
	int flag = FILENAME_FLAG;
	int bufferLen = HEADER_LENGTH + strlen(args.fromFileName);
	int state = 1;
	
	memcpy(payload, args.fromFileName, strlen(args.fromFileName));

	while(counter++ < COUNT_LIMIT){		
		sendBuf = createPDU(DEFAULT_SEQNUM, flag, payload, bufferLen);	
		safeSendto(socketNum, sendBuf, bufferLen, 0, (struct sockaddr *) server, serverAddrLen);

		if (waitForPacket(socketNum, TIMEOUT_1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, recvBuf, HEADER_LENGTH, 0, (struct sockaddr *) server, &serverAddrLen);
			if (checkCKSUM(recvBuf, dataLen)){
				if (recvBuf[6] == FILENAME_ACK_FLAG && state == 1){
					memcpy(payload, &args.windowSize, sizeof(args.windowSize));
					bufferLen = HEADER_LENGTH + sizeof(args.windowSize);
					flag = WINDOW_FLAG;
					state = 2;
				}else if (recvBuf[6] == WINDOW_ACK_FLAG && state == 2){
					memcpy(payload, &args.bufferSize, sizeof(args.bufferSize));
					bufferLen = HEADER_LENGTH + sizeof(args.bufferSize);
					flag = BUFFER_FLAG;
					state = 3;

				}else if (recvBuf[6] == BUFFER_ACK_FLAG || recvBuf[6] == DATA_FLAG){
					return 1;
				}else{ 
					continue;
				}
			}
		}
	}
	exit(-1);
}

int sendWindowSize(int socketNum, struct sockaddr_in6 *server, int windowSize){
	int serverAddrLen = sizeof(struct sockaddr_in6);
	uint8_t recvBuf[MAXBUF + 1];
	int counter = 0;
	int dataLen = 0;
	uint8_t *sendBuf;

	while(counter++ < COUNT_LIMIT){		
		sendBuf = createPDU(DEFAULT_SEQNUM, WINDOW_FLAG, (uint8_t *) &windowSize, HEADER_LENGTH + 4);
		safeSendto(socketNum, sendBuf, HEADER_LENGTH + 4, 0, (struct sockaddr *) server, serverAddrLen);
		if (waitForPacket(socketNum, TIMEOUT_1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, recvBuf, HEADER_LENGTH, 0, (struct sockaddr *) server, &serverAddrLen);
			if (checkCKSUM(recvBuf, dataLen)){
				if (recvBuf[6] == WINDOW_ACK_FLAG){
					return 1;
				}
			}
		}
	}
	exit(-1);
}

int sendBufferSize(int socketNum, struct sockaddr_in6 *server, int bufferSize){
	int serverAddrLen = sizeof(struct sockaddr_in6);
	uint8_t recvBuf[MAXBUF + 1];
	int counter = 0;
	int dataLen = 0;
	uint8_t *sendBuf;

	while(counter++ < COUNT_LIMIT){		
		sendBuf = createPDU(DEFAULT_SEQNUM, BUFFER_FLAG, (uint8_t *) &bufferSize,  HEADER_LENGTH + 4);
		safeSendto(socketNum, sendBuf, HEADER_LENGTH + 4, 0, (struct sockaddr *) server, serverAddrLen);
		if (waitForPacket(socketNum, TIMEOUT_1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, recvBuf, HEADER_LENGTH, 0, (struct sockaddr *) server, &serverAddrLen);
			if (checkCKSUM(recvBuf, dataLen)){
				if ((recvBuf[6] == BUFFER_ACK_FLAG) || (recvBuf[6] == FILE_STATUS_FLAG) || (recvBuf[6] == DATA_FLAG)){
					return 1;
				}
			}
		}
	}
	exit(-1);
}

int waitForFileStatus(int socketNum, struct sockaddr_in6 *server, char *fileName){
	int serverAddrLen = sizeof(struct sockaddr_in6);
	int counter = 0;
	int dataLen = 0;
	char recvBuf[MAXBUF + 1];
	memset(recvBuf, 0, MAXBUF + 1);
	
	while(counter++ < COUNT_LIMIT){
		if (waitForPacket(socketNum, 1)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, recvBuf, MAXBUF, 0, (struct sockaddr *) server, &serverAddrLen);
			if (checkCKSUM((uint8_t *) recvBuf, dataLen)){
				if ((recvBuf[6] == FILE_STATUS_FLAG) || (recvBuf[6] == DATA_FLAG)){
					return 1;
				}else{
					counter = COUNT_LIMIT;
				}
			}
		}
	}
	printf("Error: file %s not found on server\n", fileName);
	exit(-1);
}

FILE *openOutput(char *outputName){
	FILE *fp;
	if ((fp = fopen(outputName, "w")) == NULL){
		printf("Error could could not open file for writing: %s\n", outputName);
		perror("Error: ");
		exit(-1);
	}
	return fp;
}

int receiveDataPackets(int socketNum, struct sockaddr_in6 *server, int serverAddrLen, struct RuntimeArgs args, FILE *fp){
	uint8_t recvBuf[MAXBUF + 1];
	struct Window window = *(initWindow(args.windowSize, args.bufferSize));
	int expectedNumber = 0;
	int sequenceNumber = 0;
	int dataLen = 0;
	int counter = 0;
	int flag;
	int *test;


	while(counter++ < COUNT_LIMIT){
		memset(recvBuf, 0, MAXBUF + 1);
		if (waitForPacket(socketNum, TIMEOUT_10)){
			counter = 0;
			dataLen = safeRecvfrom(socketNum, recvBuf, MAXBUF, 0, (struct sockaddr *) server, &serverAddrLen);
			if (checkCKSUM(recvBuf, dataLen)){

				flag = processDataPacket(recvBuf, dataLen, fp, window, expectedNumber);

				if (flag == RR_FLAG){
					expectedNumber = processBuffer(fp, &window, ++expectedNumber);
				}
				if (flag == 0){
					flag == RR_FLAG;
					sendACK(socketNum, server, serverAddrLen, sequenceNumber++, expectedNumber, RR_FLAG);
					continue;
				}
				if (flag == EOF_ACK_FLAG){ 
					counter = COUNT_LIMIT + 1;
				}
				sendACK(socketNum, server, serverAddrLen, sequenceNumber++, expectedNumber, flag);
			}
		}
	}
	return 0;
}

int processDataPacket(uint8_t *recvBuf, int dataLen, FILE *fp, struct Window window, int expectedNumber) {
	uint8_t buffer[dataLen - HEADER_LENGTH];
	uint32_t sequenceNumber;

	memset(buffer, 0, dataLen);
	memcpy(buffer, recvBuf + HEADER_LENGTH, dataLen - HEADER_LENGTH);
	memcpy(&sequenceNumber, recvBuf, sizeof(sequenceNumber));
	sequenceNumber = ntohl(sequenceNumber);	
	
	if (recvBuf[6] == DATA_FLAG){
		if (sequenceNumber == expectedNumber){
			fprintf(fp, (char *) buffer);
			return RR_FLAG;
		}else if (sequenceNumber < expectedNumber){
			return 0;
		}else{
			storePacketInfo(recvBuf, dataLen, &window);
			updateWindowStatus(&window, window.currentIdx, window.lowestIdx, window.highestIdx, window.nextPos + 1);
			return SREJ_FLAG;	
		}
	}
	if (recvBuf[6] == EOF_FLAG){
		return EOF_ACK_FLAG;
	}
	return 0;
}

void storePacketInfo(uint8_t *recvBuf, int dataLen, struct Window *window){
	uint32_t sequenceNumber;
	uint8_t flag;

	memcpy(&sequenceNumber, recvBuf, sizeof(sequenceNumber));	
	memset(&flag, recvBuf + 6, sizeof(flag));
	addPacket(window, sequenceNumber, flag, recvBuf);
}

int processBuffer(FILE *fp, struct Window *window, int expectedNumber){

	while(window->lowestIdx != window->nextPos){
		if (expectedNumber == window->buffer[window->lowestIdx].sequenceNumber){
			fputs(window->buffer[window->lowestIdx].payload + HEADER_LENGTH, fp);
			expectedNumber++;
			updateWindowStatus(window, window->currentIdx, window->lowestIdx + 1, window->highestIdx + 1, window->nextPos);
		}else{
			break;
		}
	}
	return expectedNumber;
}

void sendACK(int socketNum, struct sockaddr_in6 *server, int serverAddrLen, int sequenceNumber, int payload, int flag){
	uint32_t expectedNumber = htonl(payload);
	uint8_t *sendBuf;

	if (flag == EOF_ACK_FLAG){
		sendBuf = createPDU(sequenceNumber, EOF_ACK_FLAG, (uint8_t *) "", HEADER_LENGTH);
	}else if (flag == RR_FLAG){
		sendBuf = createPDU(sequenceNumber, RR_FLAG, &expectedNumber, HEADER_LENGTH + 4);
	}else{
		sendBuf = createPDU(sequenceNumber, SREJ_FLAG, &expectedNumber, HEADER_LENGTH + 4);
	}
	safeSendto(socketNum, sendBuf, HEADER_LENGTH + 4, 0, (struct sockaddr*) server, serverAddrLen);
}

struct RuntimeArgs checkArgs(int argc, char * argv[]){
	/* check and store command line arguments  */
	struct RuntimeArgs args;

	if (argc != 8){
		printf("usage: %s from-filename to-filename window-size buffer-size error-percent remote-machine remote-port\n", argv[0]);
		exit(1);
	}
	checkFileName(argv[1]);
	checkFileName(argv[2]);
	checkWindowSize(atoi(argv[3]));
	checkBufferSize(atoi(argv[4]));
	checkErrorRate(atof(argv[5]));
	
	args.fromFileName = argv[1];
	args.toFileName = argv[2];
	args.windowSize = atoi(argv[3]);
	args.bufferSize = atoi(argv[4]);
	args.errorPercent = atof(argv[5]);
	args.remoteMachine = argv[6];
	args.remotePort = atoi(argv[7]);

	if (DEBUG){
		printf("From Filename: %s\n", args.fromFileName);
		printf("To Filename: %s\n", args.toFileName);
		printf("Window Size: %i\n", args.windowSize);
		printf("Buffer Size: %i\n", args.bufferSize);
		printf("Error Percent: %f\n", args.errorPercent);
		printf("Remote Machine: %s\n", args.remoteMachine);
		printf("Remote Port: %i\n", args.remotePort);
	}
	return args;
}

void checkFileName(char *filename){
	if (strlen(filename) > 100){
		fprintf(stderr, "Filename must be 100 characters or less\n");
		exit(-1);
	}
}

void checkWindowSize(int windowSize){
	if (windowSize <= 0){
		fprintf(stderr, "Window Size must a number be greater than 0\n");
		exit(-1);
	}
}

void checkBufferSize(int bufferSize){
	if (bufferSize <= 0){
		fprintf(stderr, "BufferSize Size must be a number greater than 0\n");
		exit(-1);
	}
}

void checkErrorRate(double errorRate){
	if ((errorRate < 0) || (errorRate > 1)){
		fprintf(stderr, "Error rate must be a number between 0 and 1\n");
		exit(-1);
	}
}

