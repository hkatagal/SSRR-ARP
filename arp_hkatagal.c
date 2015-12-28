/*
* Authors: Harishkumar Katagal(109915793) & Gagan Nagaraju (109889036)
* FileName: arp_hkatagal.c
* 
*/

#include "unp.h"
#include "arp_hkatagal.h"


struct interfaces head[20];
struct parameters parameter;
struct sockfds sockfd;
struct cache table[20];

int main(int argc, char **argv){
	int maxfd = -1;
	fd_set rset;
	int sel;
	setparameters();
	parameter.if_count = getallinterfaces();
	printallinterfaces();
	createAllsockets();
	FD_ZERO(&rset);
	for(;;){
		FD_SET(sockfd.pf,&rset);
		FD_SET(sockfd.unx,&rset);
		maxfd = max(sockfd.pf,sockfd.unx);
		maxfd = maxfd+1;
		if(sel = select(maxfd,&rset,NULL,NULL,NULL)<0){
			if(errno == EINTR)
				continue;
			else{
				perror("Select error.\n");
				break;
			}	
		}
		if(FD_ISSET(sockfd.pf,&rset)){
			handlepfpacket();
			
		}
		if(FD_ISSET(sockfd.unx,&rset)){
			
			handleunixpacket();
			
		}
		
	}
}

void createAllsockets(){
	sockfd.unx = getsockfd();
	sockfd.pf = Socket(PF_PACKET,SOCK_RAW,htons(PF_PROTO));
	Listen(sockfd.unx, LISTENQ);
}


void handlepfpacket(){
	struct arppacket arp_pkt;
	//int n;
	Recvfrom(sockfd.pf,&arp_pkt,sizeof(struct arppacket),0,NULL,NULL);
	printf("Message Received from ARP\n");
	
	if(arp_pkt.arp_pld.op == 1 && arp_pkt.arp_pld.id == htons(PROTO_ID)){
		printf("ARP Request Received\n");
		handlearprequest(&arp_pkt);
	}
	else if(arp_pkt.arp_pld.op == 2 && arp_pkt.arp_pld.id == htons(PROTO_ID)){
		printf("ARP Response Received\n");
		handlearpresponse(&arp_pkt);
	}
	
}

void handlearprequest(struct arppacket *arp_pkt){
	printarppacket(arp_pkt,2);
	updatecache(arp_pkt);
	if((strcmp(arp_pkt->arp_pld.targetIP,head[0].ipaddr))==0){
		// Send back arp response
		sendbackarp(arp_pkt);
	}
}


void handlearpresponse(struct arppacket *arp_pkt){
	int j,i;
	struct unpacket un_pkt;
	//printf("Received ARP Response\n");
	/* printf("       HW Address:");
	for(j=0;j<IF_HADDR;j++){
		printf(":%02x",arp_pkt->eth_hd.srcEth[j]);
	}
	printf("\n"); */
	printarppacket(arp_pkt,4);
	for(i=0;i<parameter.tab_count;i++){
		if((strcmp(table[i].IPaddr,arp_pkt->arp_pld.sendIP))==0){
			table[i].isvalid = 1;
			table[i].if_index = head[0].if_index;
			table[i].ha_type = arp_pkt->arp_pld.hardtype;
			memcpy(table[i].HWaddr,arp_pkt->arp_pld.sendEth,IF_HADDR);
			if(table[i].connfd != -1){
				un_pkt.ha_type = table[i].ha_type;
				un_pkt.if_index = table[i].if_index;
				memcpy(un_pkt.ip,table[i].IPaddr,IPLEN);
				memcpy(un_pkt.mac,table[i].HWaddr,IF_HADDR);
				memcpy(un_pkt.srcMAC,head[0].mac,IF_HADDR);
				Write(table[i].connfd,&un_pkt,sizeof(un_pkt));
				close(table[i].connfd);
				table[i].connfd = -1;				
			}			
			return;
		}
	}
	
	
}

void handleunixpacket(){
	int connfd;
	int n;
	struct unpacket un_pkt;
	int flag = -1;
	struct arppacket arp_pkt;
	connfd = Accept(sockfd.unx,NULL,NULL);
	Read(connfd, &un_pkt, sizeof(struct unpacket));
	printf("\n\n******************New ARP Request Received*************************\n");
	printf("IP Address requested:%s\n",un_pkt.ip);
	flag = checkincache(&un_pkt, connfd);
	/*
	* Hardware address present in cache
	*/
	if(flag == 1){
		printf("\nHW address found in Cache\n");
		Write(connfd,&un_pkt,sizeof(struct unpacket));
		printf("\n\n******************************************************************\n");
		return;
	}
	/*
	* Hardware address not present in cache
	*/
	if(flag == 0){
		//Build ARP Packet
		printf("\n HW Address Not found in cache. Hence sending broadcasting.\n");
		//printf("Message received:%s\n",un_pkt.ip);
		//Broadcast ARP Packet
		buildandbroadcastarppkt(&un_pkt);
		printf("\n\n******************************************************************\n");
	}
	
}

void printarppacket(struct arppacket *arp_pkt, int type){
	int j;
	if(type == 1){
		printf("\n**************************Outgoing ARP Broadcast************************\n");
	}
	else if(type == 2){
		printf("\n**************************Incoming ARP Request***************************\n");
	}	
	else if(type == 3){
		printf("\n**************************Outgoing ARP Reply*****************************\n");
	}
	else if(type == 4){
		printf("\n**************************Incoming ARP Reply*****************************\n");
	}
	
	printf("\n\t**************Ethernet Header********************\n");
	printf("\t\tDestination Ethernet");
	for(j=0;j<IF_HADDR;j++){
			printf(":%02x",arp_pkt->eth_hd.destEth[j]);
	}
	printf("\n\t\tSource Ethernet");
	for(j=0;j<IF_HADDR;j++){
			printf(":%02x",arp_pkt->eth_hd.srcEth[j]);
	}
	printf("\n\t\tProtocol:%d",arp_pkt->eth_hd.proto);
	printf("\n\n\t**************ARP Payload**********************\n");
	printf("\t\tIdentification Field:%d\n",arp_pkt->arp_pld.id);
	printf("\t\tHardware Type:%d",arp_pkt->arp_pld.hardtype);
	printf("\t\tProtocol:%d\n",arp_pkt->arp_pld.proto);
	printf("\t\tOperation:%d\n",arp_pkt->arp_pld.op);
	printf("\t\tSender Ethernet Adder");
	for(j=0;j<IF_HADDR;j++){
			printf(":%02x",arp_pkt->arp_pld.sendEth[j]);
	}
	printf("\n\t\tSender IP Address:%s\n",arp_pkt->arp_pld.sendIP);	
	printf("\t\tTarget Ethernet Adder");
	for(j=0;j<IF_HADDR;j++){
			printf(":%02x",arp_pkt->arp_pld.targetEth[j]);
	}
	printf("\n\t\tDestination IP Address:%s\n",arp_pkt->arp_pld.targetIP);
	printf("\n***********************************************************************\n");
}

void sendbackarp(struct arppacket *arp_pkt){
	int i=0;
	int send_result;
	struct sockaddr_ll socket_address;
	socket_address.sll_family   = PF_PACKET;
	socket_address.sll_protocol = htons(PF_PROTO);
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;
	memcpy(socket_address.sll_addr,arp_pkt->eth_hd.srcEth,IF_HADDR);
	socket_address.sll_ifindex = head[0].if_index;
	arp_pkt->arp_pld.op = 2;
	
	memcpy(arp_pkt->arp_pld.targetIP,arp_pkt->arp_pld.sendIP,IPLEN);
	memcpy(arp_pkt->arp_pld.sendIP,head[0].ipaddr,IPLEN);
	
	
	memcpy((void*)arp_pkt->arp_pld.targetEth, (void *)arp_pkt->eth_hd.srcEth, IF_HADDR);
	memcpy((void*)arp_pkt->eth_hd.destEth, (void *)arp_pkt->eth_hd.srcEth, IF_HADDR);
	memcpy((void*)arp_pkt->arp_pld.sendEth, (void *)head[0].mac, IF_HADDR);
	memcpy((void*)arp_pkt->eth_hd.srcEth, (void *)head[0].mac, IF_HADDR);
	printarppacket(arp_pkt,3);
	send_result = sendto(sockfd.pf, arp_pkt, sizeof(struct arppacket), 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
	if(send_result == -1){
			perror("Broadcast Error");
	}
	else{
		printf("Done Sending ARP Response\n");
	}
}


void buildandbroadcastarppkt(struct unpacket *un_pkt){
	int i=0;
	int if_count;
	int send_result;
	uint8_t broadMAC[] = {0xff,0xff,0xff,0xff,0xff,0xff};
	struct sockaddr_ll socket_address;
	struct arppacket arp_pkt;
	
	socket_address.sll_family   = PF_PACKET;
	socket_address.sll_protocol = htons(PF_PROTO);
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;
	memcpy(socket_address.sll_addr,broadMAC,IF_HADDR);	
	
	
	arp_pkt.arp_pld.hardtype = ARPHRD_ETHER;
	arp_pkt.arp_pld.proto = htons(PF_PROTO);
	arp_pkt.arp_pld.id = htons(PROTO_ID);
	arp_pkt.arp_pld.op = 1;
	arp_pkt.arp_pld.hardsize = 6;
	arp_pkt.arp_pld.protsize = 4;
	memcpy(arp_pkt.arp_pld.sendIP,head[0].ipaddr,IPLEN);
	memcpy(arp_pkt.arp_pld.targetIP,un_pkt->ip,IPLEN);
	arp_pkt.eth_hd.proto = htons(PF_PROTO);
	if_count = parameter.if_count;
	for(i=0;i<if_count;i++){
		memcpy((void*)arp_pkt.arp_pld.targetEth, (void *)broadMAC, IF_HADDR);
		memcpy((void*)arp_pkt.arp_pld.sendEth, (void *)head[i].mac, IF_HADDR);
		memcpy((void*)arp_pkt.eth_hd.destEth, (void *)broadMAC, IF_HADDR);
		memcpy((void*)arp_pkt.eth_hd.srcEth, (void *)head[i].mac, IF_HADDR);
		socket_address.sll_ifindex = head[i].if_index;
		printarppacket(&arp_pkt,1);
		send_result = sendto(sockfd.pf, &arp_pkt, sizeof(struct arppacket), 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
		if(send_result == -1){
			perror("Broadcast Error");
		}
		else{
			printf("Done Broadcasting\n");
		}
	}
	
	
	
}

void updatecache(struct arppacket *arp_pkt){
	int i=0;
	if(parameter.tab_count == 0){
		i = parameter.tab_count;
		table[i].isvalid = 1;
		table[i].connfd = -1;
		table[i].if_index = head[0].if_index;
		table[i].ha_type = arp_pkt->arp_pld.hardtype;
		memcpy(table[i].IPaddr,arp_pkt->arp_pld.sendIP,IPLEN);
		memcpy(table[i].HWaddr,arp_pkt->arp_pld.sendEth,IF_HADDR);
		parameter.tab_count++;
		return;
	}
	for(i=0;i<parameter.tab_count;i++){
		if((strcmp(table[i].IPaddr,arp_pkt->arp_pld.sendIP))==0){
			table[i].isvalid = 1;
			//table[i].if_index = head[0].if_index;
			//table[i].ha_type = arp_pkt->arp_pld.hardtype;
			//memcpy(table[i].IPaddr,arp_pkt->arp_pld.sendIP,IPLEN);
			memcpy(table[i].HWaddr,arp_pkt->arp_pld.sendEth,IF_HADDR);
			return;
		}
	}
	i = parameter.tab_count;
	table[i].isvalid = 1;
	table[i].connfd = -1;
	table[i].if_index = head[0].if_index;
	table[i].ha_type = arp_pkt->arp_pld.hardtype;
	memcpy(table[i].IPaddr,arp_pkt->arp_pld.sendIP,IPLEN);
	memcpy(table[i].HWaddr,arp_pkt->arp_pld.sendEth,IF_HADDR);
	parameter.tab_count++;
	return;
}

/*
* 0 - not present
* 1 - present
*/
int checkincache(struct unpacket *un_pkt, int connfd){
	int i=0;
	if(parameter.tab_count == 0){
		i = parameter.tab_count;
		table[i].isvalid = 1;
		table[i].connfd = connfd;
		table[i].if_index = -1;
		table[i].ha_type = -1;
		memcpy(table[i].IPaddr,un_pkt->ip,IPLEN);		
		parameter.tab_count++;
		return 0;
	}
	for(i=0;i<parameter.tab_count;i++){
		if((strcmp(table[i].IPaddr,un_pkt->ip))==0){
			if(table[i].isvalid == 0){
				table[i].isvalid = 1;
				table[i].connfd = connfd;
				return 0;
			}
			else{
				memcpy(un_pkt->mac,table[i].HWaddr,IF_HADDR);
				un_pkt->ha_type = table[i].ha_type;
				un_pkt->if_index = table[i].if_index;
				return 1;
			}
		}
	}
	i = parameter.tab_count;
	table[i].isvalid = 1;
	table[i].connfd = connfd;
	table[i].if_index = -1;
	table[i].ha_type = -1;
	memcpy(table[i].IPaddr,un_pkt->ip,IPLEN);		
	parameter.tab_count++;
	return 0;	
}

int getsockfd(){
	int sockfd;
	struct sockaddr_un	cliaddr;
	char cli_path[27];
	sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
	bzero(&cliaddr, sizeof(cliaddr));
	strncpy(cli_path,ARPPATH,26);
//	printf("Path : %s\n",cli_path);
	cliaddr.sun_family = AF_LOCAL;
	strcpy(cliaddr.sun_path,cli_path);
	unlink(cli_path);
	Bind(sockfd, (SA *) &cliaddr, sizeof(cliaddr));
	return sockfd;
}



void setparameters(){
	parameter.if_count = 0;
	parameter.tab_count=0;
}

void printallinterfaces(){
	int i;
	int j;
	int if_count = parameter.if_count;
	for(i=0;i<if_count;i++){
		printf("\n************************Interface 1***************************\n");
		printf("       IP Address:%s\n",head[i].ipaddr);
		printf("       HW Address:");
		for(j=0;j<IF_HADDR;j++){
			printf(":%02x",head[i].mac[j]);
		}
		printf("\n**************************************************************\n");
	}
}

int getallinterfaces(){
	int if_count = 0;
	char ip_temp[50];
	int i=0,j=0;
	struct hwa_info		*hwa, *hwahead;
	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {		
		if(strcmp(hwa->if_name,"eth0")==0){
			strncpy(head[if_count].if_name,hwa->if_name,strlen(hwa->if_name));
			head[if_count].if_index = hwa->if_index;
			bzero(&ip_temp, sizeof(ip_temp));
			Inet_ntop(AF_INET, &(((struct sockaddr_in *)hwa->ip_addr)->sin_addr),ip_temp,sizeof(ip_temp));
			strncpy(head[if_count].ipaddr,ip_temp,strlen(ip_temp));
			memcpy(head[if_count].mac, hwa->if_haddr, IF_HADDR);
			memcpy(head[if_count].if_haddr, hwa->if_haddr, IF_HADDR);
			/*printf("\nInterface\n");
			for(i=0;i<IF_HADDR;i++){
				printf("%d\t",head[if_count].mac[i]);
			}	*/
			if_count++;
			
		}
	}
	return if_count;
}
