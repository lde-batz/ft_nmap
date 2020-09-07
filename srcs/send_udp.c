/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send_udp.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/04 17:33:09 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/07 16:17:08 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*
96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/
struct pseudo_header
{
u_int32_t source_address;
u_int32_t dest_address;
u_int8_t placeholder;
u_int8_t protocol;
u_int16_t udp_length;
};
/*
Generic checksum calculation function
*/
static unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

static void	init_iphdr(struct iphdr *iph, struct sockaddr_in *source, struct sockaddr_in *sin)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = source->sin_addr.s_addr;	//Spoof the source ip address
	iph->daddr = sin->sin_addr.s_addr;
}

void	init_udphdr(struct udphdr *udph, uint16_t port)
{
	udph->source = htons (54321);
	udph->dest = htons (port);
	udph->len = htons(8);	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
}

void	pseudo_csum(struct udphdr *udph, struct sockaddr_in *source, struct sockaddr_in *dest)
{
	char *pseudogram;
	struct pseudo_header psh;
	
	/* UDP checksum with pseudo-header */
	psh.source_address = source->sin_addr.s_addr;
	psh.dest_address = dest->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);
}

void	send_udp_packet(t_thread_data *tdata, uint16_t port)
{
	int sockfd;
	char datagram[4096];
	struct sockaddr_in sin;
	struct sockaddr_in source;
	struct iphdr *iph;
	struct udphdr *udph;
	
	/* Création socket */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("Failed to create raw socket");
		exit(1);
	}
	
	/* Déclaration pointeur sur datagram */
	memset (datagram, 0, 4096);
	iph = (struct iphdr *) datagram;
	udph = (struct udphdr *) (datagram + sizeof (struct ip));
	
	/* Définition adresses source & destination */
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (inet_pton(AF_INET, tdata->src_ipv4, &source.sin_addr) != 1
		|| inet_pton(AF_INET, tdata->ipv4, &sin.sin_addr) != 1)
	{
		perror("Error inet_pton:");
		exit(EXIT_FAILURE);
	}
	
	/* Init header IP + UDP */
	init_iphdr(iph, &source, &sin);
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	init_udphdr(udph, port);

	/* Checksum with UDP pseudo-header */
	pseudo_csum(udph, &source, &sin);
	
	if (sendto (sockfd, datagram, iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
		exit(EXIT_FAILURE);
	}
	close(sockfd);
}
