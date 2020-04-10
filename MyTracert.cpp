#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <cstdio>
#include <cstdlib>
#include <winsock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_DATA_SIZE 32
#define DEFAULT_TTL 30
#define DEFAULT_RECV_TIMEOUT 3000
#define MAX_DATA_SIZE 256
#define MAX_PACKET_SIZE (MAX_DATA_SIZE + sizeof(IPHeader))

#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRE 11
#define ICMP_ECHO_REQUEST 8

#ifdef _MSC_VER
#pragma pack(1)
#endif
struct IPHeader {
	BYTE h_len : 4;           // Length of the header in dwords
	BYTE version : 4;         // Version of IP
	BYTE tos;               // Type of service
	USHORT total_len;       // Length of the packet in dwords
	USHORT ident;           // unique identifier
	USHORT flags;           // Flags
	BYTE ttl;               // Time to live
	BYTE proto;             // Protocol number (TCP, UDP etc)
	USHORT checksum;        // IP checksum
	ULONG source_ip;
	ULONG dest_ip;
};
struct ICMPHeader {
	BYTE type;          // ICMP packet type
	BYTE code;          // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
};
#ifdef _MSC_VER
#pragma pack()
#endif

// -1 if faled, 0 if ok
int resolveAddress(const sockaddr_in* dest, char* name) {
	char* buf = new char[4];
	buf[0] = dest->sin_addr.S_un.S_un_b.s_b1;
	buf[1] = dest->sin_addr.S_un.S_un_b.s_b2;
	buf[2] = dest->sin_addr.S_un.S_un_b.s_b3;
	buf[3] = dest->sin_addr.S_un.S_un_b.s_b4;

	hostent *hp = gethostbyaddr(buf, 4, dest->sin_family);
	if (hp == NULL) {
		return -1;
	}
	strcpy(name, hp->h_name);
	return 0;
}

int isAddrEqual(sockaddr_in* a1, sockaddr_in* a2) {
	if ((a1->sin_addr.S_un.S_addr == a2->sin_addr.S_un.S_addr))
		return 1;
	else
		return 0;
}

//size == icmp packet length
USHORT ICMPChecksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

// 0 if success, -1 if failure
int allocateBuffers(char* sendBuf, char* recvBuf, int dataSize)
{
	int ICMPpacketSize = dataSize + sizeof(ICMPHeader);
	sendBuf = new char[ICMPpacketSize];
	recvBuf = new char[MAX_PACKET_SIZE];
	if (!(sendBuf) && (recvBuf)) {
		printf("Failed to allocate buffers\n");
		return -1;
	}
	return 0;
}

int parseArgv(int argc, char* argv[], BOOL &lookUp, int &dataSize, DWORD &recvTO, int &maxHops) {
//	printf("%d\n", argc);
//	for (int i = 0; i < argc; i++)
//		printf("argv[%d] = %s\n", i, argv[i]);

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0) {
			dataSize = atoi(argv[i + 1]);
			if ((dataSize == 0) || (i == 1))
				return -1;
		}
		if (strcmp(argv[i], "-t") == 0) {
			recvTO = atoi(argv[i + 1]);
			if ((recvTO == 0) || (i == 1))
				return -1;
		}
		if (strcmp(argv[i], "-h") == 0) {
			maxHops = atoi(argv[i + 1]);
			if ((maxHops == 0) || (i == 1))
				return -1;
		}
		if (strcmp(argv[i], "-w") == 0) {
			lookUp = false;
			if (i == 1)
				return -1;
		}
	}
	return 1;
}

void initICMPpacket(ICMPHeader* icmpHdr, int dataSize, int seqNum)
{
	// Set up the packet's fields
	icmpHdr->type = ICMP_ECHO_REQUEST;
	icmpHdr->code = 0;
	icmpHdr->checksum = 0;
	icmpHdr->id = (USHORT)GetCurrentProcessId();
	icmpHdr->seq = seqNum;
	// data part
	memset(&icmpHdr[sizeof(ICMPHeader)], 0, dataSize);
	icmpHdr->checksum = 0;
}

void printUsage(char* argv) {
	printf("\nUsage: %s <host> [-d dataSize] [-t timeout] [-h maxHops] [-w]\n", argv);
	printf("\t-d dataSize\t Data size in packet. Data size can be up to %d. Default value is %d.\n", MAX_DATA_SIZE, DEFAULT_DATA_SIZE);
	printf("\t-t timeout\t Timeout every response, ms. Default value is %d.\n", DEFAULT_RECV_TIMEOUT);
	printf("\t-h maxHops\t Max number of hops to destination. Default value if %d.\n", DEFAULT_TTL);
	printf("\t-w\t\t Without lookup.\n\n");
}

int main(int argc, char* argv[]) {
	// start up winsock
	WSAData wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Failed to start up Winsock\n");
		return -1;
	}

	BOOL lookUp = true;
	int dataSize = DEFAULT_DATA_SIZE;
	DWORD recvTO = DEFAULT_RECV_TIMEOUT;
	int maxHops = 30;
	// check input 
	
	if ((argc > 9) || (argc < 2) || (parseArgv(argc, argv, lookUp, dataSize, recvTO, maxHops) == -1)) {
		printUsage(argv[0]);
		return -1;
	}

	// RESOLVE ADDRESSES
	// resolve the destination address
	char hostName[15];
	strcpy(hostName, argv[1]);
//	scanf("%s", hostName);

	sockaddr_in* dest = new sockaddr_in;
	memset(dest, 0, sizeof(sockaddr));

	unsigned int addr = inet_addr(hostName);
	if (addr != INADDR_NONE) {
		// It was a dotted quad number, so save result
		dest->sin_addr.s_addr = addr;
		dest->sin_family = AF_INET;
	}
	else {
		// Not in dotted quad form, so try and look it up
		hostent* hp = gethostbyname(hostName);
		if (hp != 0) {
			// Found an address for that host, so save it
			// dns roun-robin
			memcpy(&(dest->sin_addr), hp->h_addr, hp->h_length);
			dest->sin_family = hp->h_addrtype;
		}
		else {
			// Not a recognized hostname either!
			printf("Failed to resolve %s\n", hostName);
			return -1;
		}
	}
	// resolve the local address
	sockaddr_in* local = new sockaddr_in;
	memset(local, 0, sizeof(sockaddr));
	
	char localhostName[20];
	if (gethostname(localhostName, 20) == SOCKET_ERROR) {
		printf("%d", WSAGetLastError());
	}
	hostent* hp = gethostbyname(localhostName);
	if (hp != 0) {					   // i will explain this
		memcpy(&(local->sin_addr), hp->h_addr_list[2], hp->h_length);
		local->sin_family = hp->h_addrtype;
	}

	// CREATE SOCKET
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET) {
		printf("Failed to create raw socket: %d", WSAGetLastError());
		return -1;
	}
	// set receive time limit
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)& recvTO, (int)sizeof(recvTO)) == SOCKET_ERROR) {
		printf("Failed to set sock options\n");
		return -1;
	}
	// bind socket to local address; its not necessary, explanation below
//	bind(sock, (sockaddr*)local, sizeof(sockaddr));

	// ALLOCATE BUFFERS
	ICMPHeader* sendBuf = (ICMPHeader*)new char[dataSize + sizeof(ICMPHeader)];
	memset(sendBuf, 0, dataSize + sizeof(ICMPHeader));
	IPHeader* recvBuf = (IPHeader*)new char[MAX_PACKET_SIZE];
	memset(recvBuf, 0, MAX_PACKET_SIZE);
	if (!(sendBuf) && (recvBuf)) {
		printf("Failed to allocate buffers\n");
		return -1;
	}

	// Initialize icmp header
	ULONG seqNum = GetTickCount();
	initICMPpacket(sendBuf, dataSize, seqNum);

	// START TRACING
	char* hostname = new char[40];
	if ((lookUp) && (resolveAddress(dest, hostname) == 0))
		printf("Tracing to %s [%s] with max hops %d\n", hostname, inet_ntoa(dest->sin_addr), maxHops);
	else
		printf("Tracing to %s with max hops %d\n", inet_ntoa(dest->sin_addr), maxHops);


	int ttl = 1;
	do {
		// set ttl
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)& ttl, sizeof(ttl)) == SOCKET_ERROR) {
			printf("Failed to set sock options\n");
			return -1;
		}
		printf("  %d\t", ttl);
		for (int j = 0; j < 3; j++) {
			DWORD t1, t2;
			sockaddr_in* from = new sockaddr_in;
			int fromlen = sizeof(sockaddr);
			// set sequence number and checksum
			sendBuf->seq = htons(seqNum++);
			sendBuf->checksum = 0;
			sendBuf->checksum = ICMPChecksum((USHORT*)sendBuf, dataSize + sizeof(ICMPHeader));
			bool isReachable = true;
			t1 = GetTickCount();
			// If a socket is opened, a setsockopt(260th line) call is made, and then a sendto call is made, Windows Sockets performs an implicit bind function call.
			if (sendto(sock, (char*)sendBuf, dataSize + sizeof(ICMPHeader), 0, (sockaddr*)dest, sizeof(sockaddr)) == SOCKET_ERROR) {
				printf("Failed to send %d", WSAGetLastError());
				return -1;
			}
			if (recvfrom(sock, (char*)recvBuf, MAX_PACKET_SIZE, 0, (sockaddr*)from, &fromlen) == SOCKET_ERROR) {
				if (WSAGetLastError() == WSAETIMEDOUT) {
					printf("*\t");
					isReachable = false;
				}
				else {
					printf("Failed to recieve %d", WSAGetLastError());
					return -1;
				}
			}
			else {
				t2 = GetTickCount() - t1;

				if (t2 == 0) {
					printf("<1 ms\t");
				}
				else {
					printf("%d ms\t", t2);
				}
			}
			
			if (j == 2) {
				if (isReachable) {
					char* fromname = new char[40];
					if ((lookUp) && (resolveAddress(from, fromname) == 0))
						printf("%s [%s]\n", fromname, inet_ntoa(from->sin_addr));
					else
						printf("%s\n", inet_ntoa(from->sin_addr));
					if (isAddrEqual(dest, from)) {
						printf("End tracert.\n");
						goto cleanUp;
					}
				}
				else {
					printf("Destination unreachable.\n");
				}
			}
			
		}
		ttl++;
	} while (ttl <= maxHops);
cleanUp:
	closesocket(sock);
	WSACleanup();
	return 0;
}