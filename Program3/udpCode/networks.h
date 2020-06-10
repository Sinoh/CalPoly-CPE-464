
// 	Writen - HMS April 2017
//  Supports TCP and UDP - both client and server


#ifndef __NETWORKS_H__
#define __NETWORKS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BACKLOG 10
#define MAXBUF 1024

#define SETUP_FLAG 1
#define SETUP_ACK_FLAG 2
#define DATA_FLAG 3
#define NONE_FLAG 4
#define RR_FLAG 5
#define SREJ_FLAG 6
#define FILENAME_FLAG 7
#define FILENAME_ACK_FLAG 8
#define WINDOW_FLAG 9
#define WINDOW_ACK_FLAG 10
#define BUFFER_FLAG 11
#define BUFFER_ACK_FLAG 12
#define FILE_STATUS_FLAG 13
#define FILE_STATUS_REJ_FLAG 14
#define EOF_FLAG 15
#define EOF_ACK_FLAG 16

#define COUNT_LIMIT 10
#define NO_TIMEOUT 0
#define TIMEOUT_1 1
#define TIMEOUT_10 10
#define HEADER_LENGTH 7
#define DEFAULT_SEQNUM 99999
#define EMPTY_PAYLOAD 0
#define MAX_FILENAME_SIZE 100

struct Connection {
    int socketNum;
    int socketAddrLen;
    struct sockaddr_in6 *socketAddr;
};

struct RuntimeArgs {
    char *fromFileName;
    char *toFileName;
    uint32_t windowSize;
    uint32_t bufferSize;
    double errorPercent;
    char *remoteMachine;
    int remotePort;
};

struct Window {
    int windowSize;
    int closed;
    int currentIdx;
    int lowestIdx;
    int highestIdx;
    int nextPos;
    struct Packet *buffer;
};

struct Packet {
    int sequenceNumber;
    int flag;
    int packetLen;
    uint8_t *payload;
};

struct CircularBuffer {
    struct Packet *buffer;
};

//Safe sending and receiving 
int safeRecv(int socketNum, void * buf, int len, int flags);
int safeSend(int socketNum, void * buf, int len, int flags);
int safeRecvfrom(int socketNum, void * buf, int len, int flags, struct sockaddr *srcAddr, int * addrLen);
int safeSendto(int socketNum, void * buf, int len, int flags, struct sockaddr *srcAddr, int addrLen);

// for the server side
int tcpServerSetup(int portNumber);
int tcpAccept(int server_socket, int debugFlag);
int udpServerSetup(int portNumber);

// for the client side
int tcpClientSetup(char * serverName, char * port, int debugFlag);
int setupUdpClientToServer(struct sockaddr_in6 *server, char * hostName, int portNumber);

// For both
int waitForPacket(int socketNum, int timeout);
void printBytes(uint8_t *PDU, int length);
int checkCKSUM(uint8_t *aPDU, int length);
struct Packet initPacket(int bufferSize);
struct Window *initWindow(int windowSize, int bufferSize);
struct CircularBuffer *initCircularBuffer(int windowSize, int bufferSize);
int isWindowClosed(struct Window *window);
void updateWindowStatus(struct Window *window, int currentIdx, int lowestIdx, int highestIdx, int nextPos);
void addPacket(struct Window *window, int sequenceNumber, int flag, uint8_t *buffer);

uint8_t *createPDU(uint32_t sequenceNumber, uint8_t flag, uint8_t *payload, int dataLen);
void outputPDU(uint8_t *aPDU, int pduLength);
int sendInitPacket(int socketNum, struct sockaddr_in6 *srcAddr, int srcAddrLen);
int sendConnectionPackets(int socketNum, struct sockaddr_in6 *srcAddr, int srcAddrLen, uint8_t *payload, int flag);


#endif
