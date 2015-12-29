/* version 8 */

/*
* Authors: Harishkumar Katagal(109915793) & Gagan Nagaraju (109889036)
* FileName: tour_hkatagal.h
* 
*/

#ifndef TOUR_H_
#define TOUR_H_


#include "unp.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>


#define PROTOCOL 0x7847
#define PINGPROTO 0x7877
#define MYIPPROTO 187
#define IPLEN 25
#define LIST_LEN 25
#define MULTIADDR "234.147.36.196"
#define MULTIPORT "15794" 
#define IP4_HDRLEN 20  
#define IDENTIFICATION 0x7857
#define IF_HADDR 6
#define ICMP_HDRLEN 8
#define ARPPATH "/tmp/arppath_7747"

int datalen = sizeof(struct timeval);
int	nsent = 1;

struct sockfds{
	int rt; //IP raw socket - route traversal
	int pg; //IP raw socket - ping socket
	int pf_req; // PF_PACKET
	int send_udp; //UDP Send Socket
	int recv_udp; // UDP Receieve Socket
};

struct listIP{
	char vmip[IPLEN];
	int isLast;
};

struct payload{
	int index;
	uint16_t multiport;
	char multiaddr[IPLEN];	
	struct listIP ip_list[LIST_LEN];
};


struct packet{
	struct ip iphdr;
	struct payload pkt_payload;
};

struct parameters{
	int vmcount;
	char myip[IPLEN];
	int hasJoined;
	int pingcount;
	int pingstop;
	char myname[5];
	char mymac[IF_HADDR];
	uint16_t if_index;
};

struct unpacket{
	uint16_t ha_type;
	uint16_t if_index;
	char ip[IPLEN];
	char mac[IF_HADDR];
	char srcMAC[IF_HADDR];
};


struct hwaddr {
int sll_ifindex; /* Interface number */
unsigned short sll_hatype; /* Hardware type */
unsigned char sll_halen; /* Length of address */
unsigned char sll_addr[8]; /* Physical layer address */
};



struct pingdest{
	char destip[IPLEN];
	//char destmac[IF_HADDR];
	// the count is in parameter.pingcount
};

struct recvping{
	struct ip iphdr;
	struct icmp icmphdr;
}__attribute__((packed, aligned(1)));

struct ping_packet{
	char dest_mac[IF_HADDR];
	char src_mac[IF_HADDR];
	uint16_t frame_type;
	struct ip iphdr;
	struct icmp icmphdr;
}__attribute__((packed, aligned(1)));


void createAllsockfds();
void getIPAddr(char *name, char *ip);
void buildList(int argc, char **argv);
void printAllIPInTour(int len);
uint16_t checksum (uint16_t *addr, int len);
uint16_t in_cksum(uint16_t *addr, int len);
void setparameter();
void buildandsend();
void buildpacket(struct packet *pkt, int index);
void buildIPheader(struct packet *pkt, char *src_ip, char *dst_ip);
void sendpacket(struct packet *pkt,char *dest_ip);
int requestARP(char* ip_addr, struct unpacket *run_pkt);
void startping(struct packet *recv_packet, struct unpacket *run_pkt);
void reqARP(char* , struct unpacket*);
void send_v4(char* dst_mac, char* dst_ip);
void pingAll();
void proc_v4(struct recvping *recv_ping, ssize_t len, struct timeval *tvrecv);
void send_endoftour(int sockfd, SA *dest, socklen_t len);
void send_intermediate(int sockfd, SA *dest, socklen_t len, char* message_read);
void handlertpacket(struct packet *recv_packet);
int areq (struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr);


#endif
