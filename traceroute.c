#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdlib.h>
#include <string.h>
#define PCKT_LEN 8192
#define PAYLOAD "CSCI6760-f19"


struct pseudoTCPPacket {
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t TCP_len;
};


unsigned short csum(unsigned short *buf, int len)

{
	unsigned long sum;
	for(sum=0; len>0; len--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}
int main(int argc, char *argv[])
{
	int sd;
	struct iphdr *ipHdr;
	struct tcphdr *tcpHdr;
	char buffer[PCKT_LEN];

	ipHdr= (struct iphdr *) buffer;
	tcpHdr = (struct tcphdr *) (buffer + sizeof(struct iphdr));
	char *data;
	data=(char *) (buffer+ sizeof(struct iphdr) + sizeof(struct tcphdr));
	strcpy(data, PAYLOAD);

	struct pseudoTCPPacket pseudo;
	char *pseudo_pkt;
	struct sockaddr_in sin, din;

	int one = 1;
	const int *val = &one;
	memset(buffer, 0, PCKT_LEN);
	if(argc != 3)
	{
		printf("- Invalid parameters!!!\n");

		printf("- Usage: %s <Destination IP> <TCP port>\n", argv[0]);

		exit(-1);
	}

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

	if(sd < 0)
	{
		perror("socket() error");
		exit(-1);
	}
	else
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");


	sin.sin_family = AF_INET;

	din.sin_family = AF_INET;

	sin.sin_port = htons(7891);

	din.sin_port = htons(atoi(argv[2]));

	sin.sin_addr.s_addr = inet_addr(argv[1]);

	din.sin_addr.s_addr = inet_addr("192.168.0.54");


	ipHdr->ihl = 5;
	ipHdr->version = 4;
	ipHdr->tos = 16;
	ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
	ipHdr->id = htons(54321);
	ipHdr->frag_off = 0;
	ipHdr->ttl = 64;
	ipHdr->protocol = 6; 
	ipHdr->check= 0;
	ipHdr->saddr= inet_addr("192.168.0.54");

	ipHdr->daddr = inet_addr(argv[1]);

	tcpHdr->source = htons(7891);
	tcpHdr->dest = htons(atoi(argv[2]));
	tcpHdr->seq = htonl(1);
	tcpHdr->ack_seq = 0;
	tcpHdr->doff = 5;
	tcpHdr->res1 = 0;
	tcpHdr->syn = 0;
	tcpHdr->ack = 0;
	tcpHdr->window = htons(32767);
	tcpHdr->check= 0; 
	tcpHdr->urg_ptr = 0;
	tcpHdr->rst = 0;
	tcpHdr->fin = 0;
	tcpHdr->psh = 1;

	ipHdr->check= csum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcphdr)+strlen(data)));
	printf("\n checksum : %d\n",ipHdr->check);

	pseudo.srcAddr = inet_addr("192.168.0.54"); 
	pseudo.dstAddr = inet_addr(argv[1]); 
	pseudo.zero = 0; 
	pseudo.protocol = IPPROTO_TCP; 
	pseudo.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); 
	pseudo_pkt = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
	memset(pseudo_pkt, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));
	memcpy(pseudo_pkt, (char *) &pseudo, sizeof(struct pseudoTCPPacket));

	tcpHdr->check = (csum((unsigned short *) pseudo_pkt, (int) (sizeof(struct pseudoTCPPacket) +sizeof(struct tcphdr) +  
					strlen(data))));
	printf("TCP Checksum: %d\n", (int) tcpHdr->check);

	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		exit(-1);
	}
	else
		printf("setsockopt() is OK\n");
	printf("Using::::: Target IP: %s port: %u.\n", argv[1], atoi(argv[2]));

	if(sendto(sd, buffer, ipHdr->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)

	{
		perror("sendto() error");
		exit(-1);
	}
	else
		printf("Sent %d bytes ", sizeof(buffer));
	if ((recvfrom(sd, buffer, sizeof(buffer), 0,
					(struct sockaddr *) &din,sizeof(din))) < 0)
	{
		printf("\n response received\t\t\n");
		printf("Data : %s\t\tDone!\t\tSize of Buff : %d\t\tOver",buffer,sizeof(buffer));
	}
	else{
		printf("no response");}
	close(sd);
	return 0;
}
