// Ofir Rubin
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

 #define ETHER_ADDR_LEN 6

struct ethheader { // Size of 14B
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};



/* IP Header */
struct ipheader { // Size of 20B
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};



struct icmpheader{
	#define ICMP_ECHO_REQ 8
	#define ICMP_ECHO_RES 0
	#define ICMP_HDR_LEN 4
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short icmp_cksum;		/* icmp checksum */
 	unsigned short icmp_id;				/* icmp identifier */
 	unsigned short icmp_seq;			/* icmp sequence number */
};



////////////////////////////////////


// ACTUAL CODE HERE


////////////////////////////////////


// Based on the example code
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet; // Create ethernet packet from the packet data

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type | Mkae sure the ethernet header contains IP header (by given type)
    struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader)); // The IP header is located right after ethernet header. 

    if ((ip->iph_protocol) != IPPROTO_ICMP){ // Make sure this is ICMP protocol.
    	printf("Error, recieved non-ICMP packet\n");
    	return;
    }
    struct icmpheader * icmp = (struct icmpheader *) (packet + sizeof(struct ethheader) + sizeof(struct ipheader)); // The ICMP header is located  after the ethernet header and ip header.
    char ty[6]; // Most of the time we want to look for ICMP echo req/resp thus I made simple string to translate the echo type if so.
    if (icmp->icmp_code ==0){ // The type of icmp message: i.e 0 = echo reply, 3 = dest unreachable, 13 = timestamp 14 = timestamp resp
        if (icmp->icmp_type == ICMP_ECHO_REQ)
          strcpy(ty, "req");
        else
          strcpy(ty, "res");
      }
          else{
            strcpy(ty, "other");
    }
    printf("(%s) -> ", inet_ntoa(ip->iph_sourceip)); // Printing the source IP (from ip header)
    printf("(%s) |", inet_ntoa(ip->iph_destip));   // Printing the dest IP (from ip header)
    printf("ICMP(type: %d [%s], code: %d) ~ seq: %d id: %d checksum: %d ttl: %d timestamp: %ld microsec\n",
      icmp->icmp_type, ty, icmp->icmp_code, htons(icmp->icmp_seq), htons(icmp-> icmp_id), htons(icmp->icmp_cksum), ip->iph_ttl, header->ts.tv_usec); // Here we print other ICMP values and some other (ping includes ttl and RTT thus I added the ttl and timestamp (RTT is the timestamp difference between each req and resp).
	    //printf("ttl: %d | timestamp: %ld | len %d | onwire %d \n", ip->iph_ttl, header->ts.tv_sec, header->caplen, header->len);
  }

}

#define NETINTER "eth0" // can be any or interface name: I have eth0 and lo too.

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto 1"; // icmp protocol number = 1, done because icmp failed with syntax error.
  bpf_u_int32 netp;
  bpf_u_int32 maskp = 0;
  // Open live pcap session on NIC (Network interface controller) named <NETINTER>,
  //parameter value 1 allows us to "listen" to all network traffic. parameter value 1000 is timeout ms
  handle = pcap_open_live(NETINTER, BUFSIZ, 1, 1000, errbuf); 
  if (handle == NULL){
      printf("Error pcap_open_live using %s:\nerror: %s\n",  NETINTER, errbuf);
      return -1;
  }
  printf("Openned pcap live\n");

  // Get network mask
   if (pcap_lookupnet(NETINTER, &netp, &maskp, errbuf) == -1) {
     printf("Error obtainning network mask using pcap_lookupnet \n%s\n", errbuf);
     return -1;
   }

  // Compile filter_exp into BPF psuedo-code
  if (pcap_compile(handle, &fp, filter_exp, 0, maskp) != 0){
      printf("Error putting filter on the monitor\n%s\n", pcap_geterr(handle));
      return -1;
  }
  printf("pcap_compile completed\n");      
  pcap_setfilter(handle, &fp);       
  printf("pcap_setfilter passed\n");                      

  // Capture packets
  pcap_loop(handle, -1, got_packet, NULL);      
  printf("pcap_loop passed\n");          

  pcap_close(handle);   //Close the handle 
  return 0;
}

 
