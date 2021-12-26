// Ofir Rubin
// Based on Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
// 
// Sending ICMP Echo Request and recieving a reply using Raw-sockets.
//

#include <stdio.h>

#if defined _WIN32
// See at https://msdn.microsoft.com/en-us/library/windows/desktop/ms740506(v=vs.85).aspx
// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>

/*
* This stuff is not defined anywhere under MSVC.
* They were taken from the MSDN ping.c program and modified.
*/

#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0
#define IP_MAXPACKET 65535

#pragma pack(1)

struct ip
{
	UINT8   ip_hl : 4;          // length of the header
	UINT8   ip_v : 4;           // Version of IP
	UINT8   ip_tos;             // Type of service
	UINT16  ip_len;             // total length of the packet
	UINT16  ip_id;              // unique identifier of the flow
	UINT16  ip_off;				// fragmentation flags
	UINT8   ip_ttl;             // Time to live
	UINT8   ip_p;               // protocol (ICMP, TCP, UDP etc)
	UINT16  ip_sum;             // IP checksum
	UINT32  ip_src;
	UINT32  ip_dst;
};

struct icmp
{
	UINT8  icmp_type;
	UINT8  icmp_code;      // type sub code
	UINT16 icmp_cksum;
	UINT16 icmp_id;
	UINT16 icmp_seq;
	UINT32 icmp_data;      // time data
};

#pragma pack()

// MSVC defines this in winsock2.h
//typedef struct timeval {
//    long tv_sec;
//    long tv_usec;
//} timeval;

int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
    static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

    SYSTEMTIME  system_time;
    FILETIME    file_time;
    uint64_t    time;

    GetSystemTime( &system_time );
    SystemTimeToFileTime( &system_time, &file_time );
    time =  ((uint64_t)file_time.dwLowDateTime )      ;
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
    tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
    return 0;
}

#else //  linux

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#endif


//  // IPv4 header len without options
// #define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

#define SOURCE_IP "10.211.55.6"
#define DESTINATION_IP "216.58.198.78"
#define PAYLOADMSG "Ofir Rubin E5" // Message to be sent, Make sure the length is smaller than IP_MAXPACKET - 1

struct timeval startTime, stopTime;
float timedifference_msec(struct timeval t0, struct timeval t1) // https://stackoverflow.com/questions/10192903/time-in-milliseconds-in-c
{
    return (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
}

float timedifference_microsec(struct timeval t0, struct timeval t1){
		// (sec diff -> sec -> ms) -> microsec + microsec diff
	return (((t1.tv_sec - t0.tv_sec) * 1000.0f) * 1000.0f) + (t1.tv_usec - t0.tv_usec);
}

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);


int getReply(int sock, struct ip ipaddr, struct sockaddr_in dest_in, struct icmp icmphdr){
  int bytes_recv; // Size of recieved data.
  int dst_len = sizeof(dest_in); // Destination address length
  char recv_buf[256]; // recieved buffer
  if((bytes_recv = recvfrom(sock, recv_buf, sizeof(ipaddr) + sizeof(icmphdr) + sizeof(recv_buf), 0,
            (struct sockaddr *)&dest_in,(socklen_t *)&dst_len)) < 0){
        perror("recvfrom() error");
        return -1;
      }
      else{
        gettimeofday(&stopTime, NULL);
        printf("Received %d byte packet!\nRecieved: \n", bytes_recv);
      }
  for(int i=0; i < bytes_recv; i ++){
    printf("%c", recv_buf[i]);
  }
  printf("\n");
  return 1;
}

int sendRequest(struct ip ipaddr, struct sockaddr_in dest_in, struct icmp icmphdr, char data[IP_MAXPACKET]){
    // struct icmp icmphdr; // ICMP-header

    int datalen = strlen(data) + 1;

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy (packet, &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);

  #if defined _WIN32
    WSADATA wsaData = { 0 };
    int iResult = 0;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
      printf("WSAStartup failed: %d\n", iResult);
      return 1;
    }
  #endif

  // Create raw socket for ICMP
  int sock = -1;
  if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
  {
      fprintf (stderr, "socket() failed with error: %d\n"
        #if defined _WIN32
            , WSAGetLastError()
        #else
            , errno
        #endif
        );
      fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
      return -1;
  }
  // Get current time into the global variable
  gettimeofday(&startTime, NULL);
  // Send the packet using sendto() for sending datagrams.
  if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
  {
      fprintf (stderr, "sendto() failed with error: %d"
#if defined _WIN32
    , WSAGetLastError()
#else
    , errno
#endif
    );
      return -1;
  }            
  
  printf("ICMP request sucessfully sent.\n");
  return sock;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}


int main ()
{
  struct ip ipaddr; // IPv4 struct to save src and dest
  struct icmp icmphdr;
  struct sockaddr_in dest_in;
  char data[IP_MAXPACKET] = PAYLOADMSG;
  strcat(data, "\n");
  
  // Set ipaddr:
  // Set source IP into ipaddr
  if (inet_pton (AF_INET, SOURCE_IP, &(ipaddr.ip_src)) <= 0) 
  {
      fprintf (stderr, "inet_pton() failed for source-ip with error: %d"
          #if defined _WIN32
                , WSAGetLastError()
          #else
                , errno
          #endif
                );
      return -1;
  }

  // Set dest IP into ipaddr
  if (inet_pton (AF_INET, DESTINATION_IP, &(ipaddr.ip_dst)) <= 0)
  {
      fprintf (stderr, "inet_pton() failed for destination-ip with error: %d" 
          #if defined _WIN32
                , WSAGetLastError()
          #else
                , errno
          #endif
                );
      return -1;
  }
  //////////////////

  // Set dest_in:
  memset (&dest_in, 0, sizeof (struct sockaddr_in));
  dest_in.sin_family = AF_INET;

  //The port is irrelant for Networking and therefore was zeroed.
  #if defined _WIN32
      dest_in.sin_addr.s_addr = iphdr.ip_dst;
  #else
      dest_in.sin_addr.s_addr = ipaddr.ip_dst.s_addr;
  #endif
  //////////////

  int sock = sendRequest(ipaddr, dest_in, icmphdr, data);
  if (sock == -1)
  {
    return 1;
  }
  if (getReply(sock, ipaddr, dest_in, icmphdr)){
    printf("time ms: %.6f\n", timedifference_msec(startTime, stopTime));
    printf("time in microsec: %f\n", timedifference_microsec(startTime, stopTime));
  }
  // Close the raw socket descriptor.
  #if defined _WIN32
    closesocket(sock);
    WSACleanup();
  #else
    close(sock);
  #endif
  return 0;
}

