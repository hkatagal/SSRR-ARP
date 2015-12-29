/*
* Authors: Harishkumar Katagal(109915793) & Gagan Nagaraju (109889036)
* FileName: arp_hkatagal.h
* 
*/

#ifndef ARP_H_
#define ARP_H_


#include "unp.h"
#include "hw_addrs.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>







#define	IF_HADDR 6
#define IF_NAME 16
#define IPLEN 25
#define PF_PROTO 0x8847
#define PROTOCOL 0x8447
#define PROTO_ID 0x8347
#define ARPPATH "/tmp/arppath_7747"


struct interfaces{
	int sockfd;
	char    if_name[IF_NAME];	/* hardware address */
	int     if_index;		/* interface index */
	char ipaddr[IPLEN];	/* IP address */
	uint8_t mac[IF_HADDR];
	char    if_haddr[IF_HADDR];
};

struct parameters{
	int if_count;
	int tab_count;
};

struct sockfds{
	int pf;
	int unx;
};



struct cache{
	int isvalid;
	int connfd;
	uint16_t if_index;
	uint16_t ha_type;
	char IPaddr[IPLEN];
	uint8_t HWaddr[IF_HADDR];
};


struct eth_header{
	uint8_t destEth[IF_HADDR];
	uint8_t srcEth[IF_HADDR];
	uint16_t proto;
};

struct arp_payload{
	uint16_t id;
	uint16_t hardtype;//type of hardware
	uint16_t proto; //PROTOCOL
	uint8_t hardsize;
	uint8_t protsize;
	uint16_t op; //ARP REQ 1 & ARP RES 2
	uint8_t sendEth[IF_HADDR];
	char sendIP[IPLEN];
	uint8_t targetEth[IF_HADDR];
	char targetIP[IPLEN];
};

struct arppacket{
	struct eth_header eth_hd;
	struct arp_payload arp_pld;
};

struct unpacket{
	uint16_t ha_type;
	uint16_t if_index;
	char ip[IPLEN];
	uint8_t mac[IF_HADDR];
	uint8_t srcMAC[IF_HADDR];
};

void setparameters();
void printallinterfaces();
int getallinterfaces();
void createAllsockets();
void handleunixpacket();
int checkincache(struct unpacket *pf_pkt, int connfd);
int getsockfd();
void buildandbroadcastarppkt(struct unpacket *un_pkt);
void handlepfpacket();

#endif
