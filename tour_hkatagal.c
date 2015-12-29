/*version 8 */

/*
* Authors: Harishkumar Katagal(109915793) & Gagan Nagaraju (109889036)
* FileName: tour_hkatagal.c
* 
*/
#include "unp.h"
#include "tour_hkatagal.h"

struct sockfds sockfd;
struct listIP ip_list[LIST_LEN];
struct parameters parameter;
struct pingdest ping_dst[50];

// Used for MultiCast
socklen_t			salen;
struct sockaddr		*sasend, *sarecv;

static void sig_alarm(int);

int main(int argc, char **argv){
	int i;	
	int			maxfdp1, n;
	fd_set		rset;
	struct packet *recv_packet = (struct packet *)malloc(sizeof(struct packet));
	
	struct recvping recv_ping;
	
	//struct packet recv_packet
	// free it later.....
	char time_buff[MAXLINE], srcIP[INET_ADDRSTRLEN], buff[MAXLINE], recvbuff[MAXLINE];
	time_t ticks;
	struct in_addr addr;
	struct msghdr	msg;
	struct iovec	iov;
	struct timeval tval;
	// Used for receiving ping packets from pg socket
	SA * destaddr;
	//bzero(destaddr, sizeof(destaddr));
	socklen_t destlen;
	
	int index;	
	
	createAllsockfds();
	setparameter();
	
	Signal(SIGALRM, sig_alarm);
	
	/* Read command line arguments */
	if(argc<2){
		printf("Not source of Tour\n");
		//exit(0);
	}
	else{
		printf("Source of the Tour\n");
		printf("Nodes to be visited in the tour:\n");
		for(i=1;i<argc;i++){
			printf("Node: %d : %s\n",i,argv[i]);
		}
		buildList(argc,argv);
		/* build packet and send to next address */
		buildandsend();
		
	}
	FD_ZERO(&rset);
		for( ; ; ){
						
			FD_SET(sockfd.rt, &rset);
			FD_SET(sockfd.recv_udp, &rset);
			FD_SET(sockfd.pg, &rset);
			maxfdp1 = max(sockfd.rt, max(sockfd.recv_udp, sockfd.pg)) + 1;
			
			// Select is used to monitor rt socket and....
			if( select(maxfdp1, &rset, NULL, NULL, NULL) < 0){
				if(errno == EINTR)
					continue;
				else
					err_sys("Select Error");
			}
			
			if (FD_ISSET(sockfd.rt, &rset)) {	
				if ( (n = recvfrom(sockfd.rt, recv_packet, sizeof(struct packet), 0, NULL, NULL)) < 0) {
						if(errno == EINTR)
							continue;
						else
							err_sys("Read Error");
				}
				handlertpacket(recv_packet);
				// get the IP and mac addr and start pinging if a previous node exists
				
			}
			if( FD_ISSET(sockfd.recv_udp, &rset) ){
				alarm(0);
				//Disable the alarm
				parameter.pingstop = 1;	
				bzero(buff,MAXLINE);
				if( read(sockfd.recv_udp, buff, MAXLINE) < 0){
					if(errno == EINTR)
						continue;
					else
						err_sys("Read error");
				}				
				send_intermediate(sockfd.send_udp, sasend, salen, buff);
				//alarm(5);
				while( (n = readable_timeo(sockfd.recv_udp, 5)) >= 0){
					if(n < 0){
						if(errno = EINTR)
							continue;
						else
							err_sys("Readable Timeo error");
					}
					else if(n == 0){
						printf("\n**********Exiting the process after 5 seconds***********\n");
						exit(1);
					}										
					else{
						bzero(buff,MAXLINE);
						Read(sockfd.recv_udp, buff, MAXLINE);
						printf("\tNode %s: Received Multicast Message: %s\n",parameter.myname, buff);	
					}					
				}								
			}
			if (FD_ISSET(sockfd.pg, &rset)){
				// process the ping packet received and display the info				
				//printf("\n\n *************** PING PACKET RECEIVED*******\n\n");
				msg.msg_name = destaddr;
				msg.msg_namelen = destlen;
				msg.msg_iov = &iov;
				msg.msg_iovlen = 1;
				//msg.msg_control = controlbuf;
				iov.iov_base = recvbuff;
				iov.iov_len = sizeof(recvbuff);
				//n = recvmsg(sockfd.pg, &msg, 0);
				n = Recvfrom(sockfd.pg,&recv_ping,sizeof(struct recvping),0,NULL,NULL);
				/* if(n < 0){
					if(errno == EINTR)
						continue;
					else
						err_sys("Recvmsg Error");
				} */
				Gettimeofday(&tval, NULL);
				proc_v4(&recv_ping, n, &tval); 				
			}
		}	
}
/* End of main() */

void handlertpacket(struct packet *recv_packet){
	int index;
	time_t ticks;
	char time_buff[MAXLINE];
	struct hostent *hptr;
	int status;
	int flag;
	struct unpacket run_pkt;
	char temp_addr[IPLEN];
	char *temp_addr1;
	
	index = recv_packet->pkt_payload.index+1;
	if(recv_packet->iphdr.ip_id == htons(IDENTIFICATION)){
		ticks = time(NULL);
		snprintf(time_buff, sizeof(time_buff), "%.24s", ctime(&ticks));
		if((hptr = gethostbyaddr(&(recv_packet->iphdr.ip_src),sizeof(struct in_addr),AF_INET))==NULL)
			err_sys("Error: Invalid IP address. Terminating.");
		printf("\n\n*************************Source Routing Packet Received***********");
		printf("\n\t%s received source routing packet from %s\n", time_buff, hptr->h_name);
		//memcpy(&temp_addr,hptr->h_addr,IPLEN);
		temp_addr1 = inet_ntoa(recv_packet->iphdr.ip_src);
		memcpy(&temp_addr,recv_packet->pkt_payload.ip_list[index-2].vmip,IPLEN);
		printf("\tRequesting ARP for:%s\n",temp_addr1);
		flag = requestARP(&temp_addr, &run_pkt);
		
		bzero(&(parameter.mymac), sizeof(parameter.mymac));
		memcpy(&(parameter.mymac), run_pkt.srcMAC, strlen(run_pkt.srcMAC));
		parameter.if_index = run_pkt.if_index;
		
		if(flag == 1){
			//Start pinging with MAC
			//mac is in run_pkt->mac
			
			startping(recv_packet,&run_pkt);	
			
		}
		
		if(recv_packet->pkt_payload.ip_list[index-1].isLast){
			printf("\nI am the last node in the tour\n");
		}
		else{
			if ((status = inet_pton (AF_INET, &(parameter.myip), &(recv_packet->iphdr.ip_src))) != 1){
				fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
				exit (EXIT_FAILURE);
			}
			if ((status = inet_pton (AF_INET, &(recv_packet->pkt_payload.ip_list[index].vmip), &(recv_packet->iphdr.ip_dst))) != 1) {
			fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
			exit (EXIT_FAILURE);
			}		
			recv_packet->pkt_payload.index++;
			sendpacket(recv_packet,&(recv_packet->pkt_payload.ip_list[index].vmip));
		}
		
		// Join the multicast group using multicast address and port number			
		if(parameter.hasJoined == 0){
				Mcast_join(sockfd.recv_udp, sasend, salen, NULL, 0);
				parameter.hasJoined = 1;
		}
		
		if(recv_packet->pkt_payload.ip_list[index-1].isLast){
			send_endoftour(sockfd.send_udp, sasend, salen);
		}
	}
	else{
		printf("Wrong packet received, ignoring it\n");		
	}
}

void send_endoftour(int sockfd, SA *dest, socklen_t len){
	char message[MAXLINE];
	printf("\n\n****************Starting MultiCast Messages*******************\n");
	snprintf(message, sizeof(message), "This is node %s. Tour has ended. Group members please identify yourself\n",parameter.myname);

	// Stop pinging activity
	Sendto(sockfd, message, strlen(message), 0, dest, len);
	
	printf("Node %s: Sending Multicast Message: This is node %s. Tour has ended. \
	Group members please identify yourself\n", parameter.myname, parameter.myname);
}

void send_intermediate(int sockfd, SA *dest, socklen_t len, char* message_read){
	char message[MAXLINE];
	snprintf(message, sizeof(message), "Node %s. I am a member of the group\n",parameter.myname);
			
	// Stop the pinging activity
	printf("\n\n************* Starting MultiCast Replies**************\n");
	printf("\tNode %s: Received Multicast Message: %s\n", parameter.myname, message_read);	
	Sendto(sockfd, message, strlen(message), 0, dest, len);	
	printf("\tNode %s: Sending Mulicast Message: %s\n", parameter.myname, message);	
}

void startping(struct packet *recv_packet, struct unpacket *run_pkt){
	/* Add the ip address of the destination to the struct pingdest */
	char buff[IPLEN];
	int i;
	
	bzero(buff, sizeof(buff));
	Inet_ntop(AF_INET, &(recv_packet->iphdr.ip_src), buff, sizeof(buff));
	
	for(i=0; i<parameter.pingcount; i++){			
		if(strcmp(buff, &(ping_dst[i].destip)) == 0)
			//break;
			return;
	}
	if(i==parameter.pingcount){
		bzero( &(ping_dst[i].destip), IPLEN );
		memcpy( &(ping_dst[i].destip), buff, IPLEN);
		
		/*bzero( &(ping_dst[i].destmac), sizeof(ping_dst[i].destmac) );
		memcpy( &(ping_dst[i].destmac), run_pkt->mac, strlen(run_pkt->mac) );*/
		
		parameter.pingcount++;			
	}	
	pingAll();
	
	alarm(1);
	
}

void pingAll(){
	//Use for loop, requestARP, send the ping packets
	int i;
	struct unpacket run_pkt;
	for(i=0; i<parameter.pingcount; i++){
		requestARP(&(ping_dst[i].destip), &run_pkt);
		send_v4(&run_pkt.mac, &(ping_dst[i].destip));
	}
	//alarm(1);
}

void send_v4(char* dst_mac, char* dst_ip)
{
	struct sockaddr_ll socket_address;
	struct in_addr  ipaddr;
	int ip_flags[4];
	int i, len, frame_length;
	struct hostent	*hptr;
	for(i=0; i<4; i++)
		ip_flags[i] = 0;
	
	struct ping_packet ping_pkt;
	Inet_pton(AF_INET, dst_ip, &ipaddr);
	if ( (hptr = gethostbyaddr(&ipaddr, sizeof(ipaddr), AF_INET)) == NULL) {
		err_msg("gethostbyname error for host: %s: %s",
				dst_ip, hstrerror(h_errno));
		exit(1);
	}
	printf("\n\n ******************Sending Ping*****************\n");
	printf("\tPING %s (%s): %d data bytes\n",
			hptr->h_name ? hptr->h_name : dst_ip, dst_ip, datalen);
	printf("\n\n ***********************************************\n");
	bzero(&(ping_pkt.dest_mac), IF_HADDR);
	memcpy(&(ping_pkt.dest_mac), dst_mac, IF_HADDR);
	
	bzero(&(ping_pkt.src_mac), IF_HADDR);
	memcpy(&(ping_pkt.src_mac), &(parameter.mymac), IF_HADDR);
	
	ping_pkt.frame_type = htons(ETH_P_IP);
	
	
	// IPV4 header
	ping_pkt.iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);
	ping_pkt.iphdr.ip_v = 4;
	ping_pkt.iphdr.ip_tos = 0;
	ping_pkt.iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);
	ping_pkt.iphdr.ip_id = htons (PINGPROTO);
	ping_pkt.iphdr.ip_off = htons ((ip_flags[0] << 15)+(ip_flags[1] << 14)+(ip_flags[2] << 13)+ip_flags[3]);
	ping_pkt.iphdr.ip_ttl = htons(1);
    ping_pkt.iphdr.ip_p = IPPROTO_ICMP;
	
	Inet_pton (AF_INET, &(parameter.myip), &(ping_pkt.iphdr.ip_src));
	
	Inet_pton (AF_INET, dst_ip, &(ping_pkt.iphdr.ip_dst));
	
	ping_pkt.iphdr.ip_sum = 0;
	ping_pkt.iphdr.ip_sum = checksum ((uint16_t *) &(ping_pkt.iphdr), IP4_HDRLEN);	
	
	// ICMP header and data
	ping_pkt.icmphdr.icmp_type = ICMP_ECHO;
	ping_pkt.icmphdr.icmp_code = 0;
	ping_pkt.icmphdr.icmp_id = htons(PINGPROTO);
	ping_pkt.icmphdr.icmp_seq = nsent++;
	//memset(&(ping_pkt.icmphdr.icmp_data), 0xa5, datalen);	/* fill with pattern */
	Gettimeofday((struct timeval *) &(ping_pkt.icmphdr.icmp_data), NULL);
	
	len = ICMP_HDRLEN + datalen;		/* checksum ICMP header and data */
	ping_pkt.icmphdr.icmp_cksum = 0;
	ping_pkt.icmphdr.icmp_cksum = in_cksum((uint16_t *) &(ping_pkt.icmphdr), len);		
	
	frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen; 
	
	// Fill the socket address to Sendto
	bzero(&socket_address, sizeof(socket_address));
	
	
	
	socket_address.sll_ifindex = parameter.if_index;
	socket_address.sll_family = PF_PACKET;
	memcpy(&socket_address.sll_addr, dst_mac, IF_HADDR);
	socket_address.sll_halen = 6;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_pkttype = PACKET_OTHERHOST;
	//printf("Sending Ping packet\n");
	// Send the packet
	Sendto(sockfd.pf_req, &ping_pkt, frame_length, 0, (SA*) &socket_address, sizeof(socket_address));	
}

void proc_v4(struct recvping *recv_ping, ssize_t len, struct timeval *tvrecv)
{
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;
	char temp_ipaddr[IPLEN];
	
	//ip = (struct ip *) ptr;		/* start of IP header */
	ip = &(recv_ping->iphdr);
	hlen1 = ip->ip_hl << 2;		/* length of IP header */
	/* if (ip->ip_p != IPPROTO_ICMP){
		printf("Not ICMP:%d\t%d\t%d\n",recv_ping->iphdr.ip_p,ip->ip_p,IPPROTO_ICMP);
		return;				/* not ICMP 
	} */

	//icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	icmp = &(recv_ping->icmphdr);
	//printf("\n\nLEN: %d, HLEN: %d\n\n",len,hlen1);
	if ( (icmplen = len - hlen1) < 8){
		printf("Malformed Packet\n");
		return;				/* malformed packet */
		
	}

	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		printf("\n Ping Reply: ");
	}
	else if(icmp->icmp_type == ICMP_ECHO){
		printf("\n Ping Request: ");		
	}
	if (icmp->icmp_id != htons(PINGPROTO)){
		printf("ICMP ID Not matching: %d\t%d\n",icmp->icmp_id,htons(PINGPROTO));

		return;			/* not a response to our ECHO_REQUEST */
	}
	if (icmplen < 16){
		printf("not enough data to use\n");
		return;			/* not enough data to use */
	}

	tvsend = (struct timeval *) icmp->icmp_data;
	tv_sub(tvrecv, tvsend);
	rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
	inet_ntop(AF_INET,&(ip->ip_src),&temp_ipaddr,IPLEN);
	printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
			icmplen, temp_ipaddr,icmp->icmp_seq, ip->ip_ttl, rtt);
	//} 
}


int areq (struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr){
	struct unpacket un_pkt;
	printf("\n Sending ARP Request\n");
}


int requestARP(char* ip_addr, struct unpacket *run_pkt){
	int unsockfd;
	int j;
	struct unpacket un_pkt;
	//struct unpacket run_pkt;
	struct sockaddr_un addr;
	struct timeval timer;
	fd_set		allset;
	int maxfdp;
	char cli_path[27];
	uint8_t broadMAC[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	
	
	bzero(&addr, sizeof(addr));
	strncpy(cli_path,ARPPATH,26);
	unsockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path,cli_path);
	
	//inet_ntop(AF_INET, (ip_addr), &(un_pkt.ip), IPLEN);
	memcpy(&(un_pkt.ip),ip_addr,IPLEN);
	//printf("Inside IP:%s\n",un_pkt.ip);
	printf("\n\n*****************************ARP******************************\n");
	printf("\tRequesting ARP for IP: %s\n",un_pkt.ip);
	memcpy(&(un_pkt.mac),broadMAC,IF_HADDR);
	Connect(unsockfd,(SA *)&addr,sizeof(addr));
	Write(unsockfd,&un_pkt,sizeof(un_pkt));
	FD_ZERO(&allset);
	timer.tv_sec = 5;
	timer.tv_usec = 0;
	for( ; ; ){						
		FD_SET(unsockfd, &allset);
		maxfdp = unsockfd + 1;
		Select(maxfdp, &allset, NULL, NULL, &timer);
		if( FD_ISSET(unsockfd, &allset) ){
			Read(unsockfd, run_pkt, sizeof(struct unpacket));
			printf("\t*************ARP REPLY******************\n");
			printf("\t\tHW Address received:");
			for(j=0;j<IF_HADDR;j++){
				printf(":%02x",run_pkt->mac[j]);
			}
			printf("\n*****************************************************\n\n");
			break;
		}
		else{
			printf("Timeout on ARP Request.\n");
			return 0;
		}
	}
	//printf("MAC Done\n");
	close(unsockfd);
	/* while(1){
	} */
	return 1;
}


void setparameter(){
	char hostname[128];
	bzero(hostname,128);
	gethostname(hostname,128);
	memcpy(parameter.myname,hostname,5);
	parameter.vmcount = 0;
	parameter.pingcount = 0;
	parameter.pingstop = 0;
	parameter.hasJoined = 0;
	parameter.if_index = 0;
	getIPAddr(&hostname,&(parameter.myip));
}

/*
* buildandsend packet to next vm
*/
void buildandsend(){
	struct packet pkt;
	buildIPheader(&pkt,&(parameter.myip),&(ip_list[1].vmip));
	//printf("Printing\n");
	//printf("IPv inside build and send:%d\n",pkt.iphdr.ip_v);
	buildpacket(&pkt,1);
//	printf("packet Index: %d\n",pkt.pkt_payload.index);
	//printf("Actual Packet size:%d\n",sizeof(pkt));
	sendpacket(&pkt,&(ip_list[1].vmip));
}

void sendpacket(struct packet *pkt,char *dest_ip){
	int s;
	struct packet pkt_send;
	struct sockaddr_in dest;
	
	//char destip[IPLEN];
	bzero(&dest,sizeof(dest));
	dest.sin_family = AF_INET;
	//dest.sin_port = 15797;
	inet_pton(AF_INET,dest_ip,&(dest.sin_addr.s_addr));
	/*printf("Before send dest:%s\n",dest_ip);
	printf("packet Index: %d\n",pkt->pkt_payload.index);*/
	if((s=sendto(sockfd.rt,pkt,sizeof(struct packet),0,(SA *)&dest,sizeof(dest)))<0){
		
		perror("Error:");
		exit(0);
	}
}


void buildpacket(struct packet *pkt, int index){
	pkt->pkt_payload.index = index;
	pkt->pkt_payload.multiport = MULTIPORT;
	strcpy(pkt->pkt_payload.multiaddr,MULTIADDR);
	memcpy(pkt->pkt_payload.ip_list,ip_list,sizeof(ip_list));
}


void buildIPheader(struct packet *pkt, char *src_ip, char *dst_ip){
	char str[INET_ADDRSTRLEN];
	int status;
	pkt->iphdr.ip_hl = sizeof(struct ip) / sizeof (uint32_t);
	printf("IP_HL:%d\n",pkt->iphdr.ip_hl);
	pkt->iphdr.ip_v = IPVERSION;

	  // Type of service (8 bits)
	  pkt->iphdr.ip_tos = 0;

	  // Total length of datagram (16 bits): IP header + TCP header
	  pkt->iphdr.ip_len = htons(sizeof(struct packet));
	  printf("IP LEN:%d\n",pkt->iphdr.ip_len);
	  printf("IP1 LEN:%d\n",sizeof(struct payload));

	  // ID sequence number (16 bits): unused, since single datagram
	  pkt->iphdr.ip_id = htons(IDENTIFICATION);

	  pkt->iphdr.ip_off = 0;

	  // Time-to-Live (8 bits): default to maximum value
	  pkt->iphdr.ip_ttl = 1;

	  // Transport layer protocol (8 bits): 6 for TCP
	  pkt->iphdr.ip_p = MYIPPROTO;
	  //printf("SRC IP:%s\n",src_ip);
	  //printf("DEst IP:%s\n",dst_ip);
	  if ((status = inet_pton (AF_INET, src_ip, &(pkt->iphdr.ip_src))) != 1) {
			fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
			exit (EXIT_FAILURE);
	  }
	  
	  

	  // Destination IPv4 address (32 bits)
	  if ((status = inet_pton (AF_INET, dst_ip, &(pkt->iphdr.ip_dst))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	  }
	  /* inet_ntop(AF_INET, &(pkt->iphdr.ip_dst), str, INET_ADDRSTRLEN);
	  printf("SRC IP NTOP:%s\n",str); */
	  pkt->iphdr.ip_sum = 0;
	  //pkt->iphdr.ip_sum = checksum((uint16_t *) pkt, sizeof(struct packet));
	 // printf("Inside Build IP\n");
	 // printf("IP_SUM:%d\n",pkt->iphdr.ip_sum);
	
}
/*
* To create all sockets required for communication
*/
void createAllsockfds(){
	/* Two IP raw sockets, one PF_PACKET and a UDP socket*/
	
	struct sockaddr_ll socket_address;
	int flag = 1;
	
	//IP raw socket - route traversal - rt
	sockfd.rt = Socket(AF_INET,SOCK_RAW,MYIPPROTO);
	if(setsockopt(sockfd.rt,  IPPROTO_IP, IP_HDRINCL, &flag,sizeof(flag))<0)
		err_quit("Cannot set IP_HDRINCL socket option\n");
	
	
	
	//IP raw socket - ping socket - pg
	sockfd.pg = Socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
	
	
	// PF_PACKET - pf
	/* socket_address.sll_family   = PF_PACKET;
	socket_address.sll_protocol = htons(PROTOCOL);
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;	 */
	sockfd.pf_req = Socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	
	
	
	//UDP Send Socket
	sockfd.send_udp = Udp_client(MULTIADDR, MULTIPORT, (void **) &sasend, &salen);
	
	//UDP Receieve Socket
	sockfd.recv_udp = Socket(sasend->sa_family, SOCK_DGRAM, 0);
	
	if (setsockopt(sockfd.recv_udp, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
        err_quit("Cannot set reuse address on UDP socket");
	
	sarecv = Malloc(salen);
	memcpy(sarecv, sasend, salen);
	Bind(sockfd.recv_udp, sarecv, salen);	
	
}

void buildList(int argc, char **argv){
	int i;
	char hostname[128];
	gethostname(hostname,128);
	getIPAddr(&hostname,&(ip_list[0].vmip));
	ip_list[0].isLast=0;
	for(i=1;i<argc;i++){
		getIPAddr(argv[i],&(ip_list[i].vmip));
		ip_list[i].isLast=0;
	}	
	ip_list[i-1].isLast = 1;
	printAllIPInTour(argc);
}


void printAllIPInTour(int len){
	int i;
	for(i=0;i<len;i++){
		printf("Node %d: IP: %s\n",i,ip_list[i].vmip);
	}
}

void getIPAddr(char *name, char *ip){
	struct hostent *hptr;
	char **pptr;
	char str[INET_ADDRSTRLEN];
	const char *serverip, *destIP;
	if((hptr = gethostbyname(name))==NULL){
		perror("Error: Invalid host name. Terminating.");
		exit(0);
	}
	pptr = hptr->h_addr_list;
	destIP = Inet_ntop(hptr->h_addrtype,*pptr,str,sizeof(str));
	bzero(ip,sizeof(ip));
	memcpy(ip,destIP,IPLEN);
	//printf("Dest ip: %s\n",destIP);
}

uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

uint16_t in_cksum(uint16_t *addr, int len)
{
	int				nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

		/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

static void sig_alarm(int signo){
	if(parameter.pingstop == 0){
		pingAll();
		alarm(1);
	}
	else
		alarm(0);	
	return;
}

void reqARP(char* str, struct unpacket* pkt){
	struct sockaddr IPaddr;
	socklen_t sockaddrlen;
	struct hwaddr *HWaddr;
	//struct hwaddr HWaddr;
	areq(&IPaddr, sockaddrlen, HWaddr);
	
}

