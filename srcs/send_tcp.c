/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send_tcp.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/04 15:26:21 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/05 13:02:19 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int		init_socket(void)
{
	int	sockfd;

/*		Ouverture du socket raw de protocol TCP		*/
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
	{
		perror("Error creating socket:");
		exit(EXIT_FAILURE);
	}

/*		IP_HDRINCL pour indiquer au noyau que les en-têtes sont inclus dans le paquet		*/
	int one = 1;
	const int *val = &one;
	
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setsockopt:");
		exit(EXIT_FAILURE);
	}
	return (sockfd);
}

void	init_iphdr(char *datagram, struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	struct iphdr	*iph;

	iph = (struct iphdr *)datagram;
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = saddr->sin_addr.s_addr;
	iph->daddr = daddr->sin_addr.s_addr;
	iph->check = checksum((unsigned short *)datagram, sizeof(iph));
}

void	init_tcphdr(struct tcphdr *tcph, uint8_t type, uint16_t port)
{
	tcph->source = htons(54321);
	tcph->dest = htons(port);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin = (type & SCAN_FIN || type & SCAN_XMAS) ? 1 : 0;
	tcph->syn = (type & SCAN_SYN) ? 1 : 0;
	tcph->rst = 0;
	tcph->psh = (type & SCAN_XMAS) ? 1 : 0;
	tcph->ack = (type & SCAN_ACK) ? 1 : 0;
	tcph->urg = (type & SCAN_XMAS) ? 1 : 0;
	tcph->window = 0;
	tcph->check = 0;
	tcph->urg_ptr = 0;
}

/*		checksum HEADER TCP		*/
int		tcphdr_checksum(struct tcphdr *tcph, struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
	t_pseudo_header	psh;	// obligatoire pour le calcul du checksum

	psh.source_address = saddr->sin_addr.s_addr;
	psh.dest_address = daddr->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

	return (checksum((unsigned short *)&psh, sizeof(t_pseudo_header)));
}

void	send_tcp_packet(char *device, t_thread_data *data, uint8_t type, uint16_t port)
{
	int					sockfd;
	char				datagram[512];
	char				ip_source[64]; // 64 a modifier ?
	struct tcphdr		*tcph;
	struct sockaddr_in	saddr;
	struct sockaddr_in	daddr;


/*		Initialisation du socket TCP		*/
	sockfd = init_socket();


/* Obtention de l'ip du device */
	struct ifaddrs	    *ifap;
	struct ifaddrs		*p;
	struct sockaddr_in	*sa;
		
	if (getifaddrs(&ifap) == -1)
		return ;
	p = ifap;
	while (p)
	{
		if (p->ifa_addr->sa_family == AF_INET && strcmp(p->ifa_name, device) == 0)
		{
			sa = (struct sockaddr_in *)p->ifa_addr;
			ft_strcpy(ip_source, inet_ntoa(sa->sin_addr));
			break;
		}
		p = p->ifa_next;
	}

/*		Initialisation adresse source		*/
	if (inet_pton(AF_INET, ip_source, &saddr.sin_addr) != 1)
	{
		perror("Error inet_pton:");
		exit(EXIT_FAILURE);
	}

/*		Initialisation adresse destination		*/
	daddr.sin_family = AF_INET;
	if (inet_pton(AF_INET, data->ipv4, &daddr.sin_addr) != 1)
	{
		perror("Error inet_pton:");
		exit(EXIT_FAILURE);
	}

/*		Initialisation du datagram		*/
	ft_bzero(datagram, sizeof(datagram));

/*		Initialisation HEADER IP		*/
	init_iphdr(datagram, &saddr, &daddr);

/*		Initialisation HEADER TCP		*/
	tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
	init_tcphdr(tcph, type, port);
	tcph->check = tcphdr_checksum(tcph, &saddr, &daddr);


/*		Envoie du packet TCP		*/
	//dprintf(2, "Envoi packet dest: %s port %s source %s port %s \n", saddr.sin_addr.s_addr);
	if (sendto(sockfd, datagram, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr *)&daddr, sizeof(daddr)) < 0)
	{
		perror("Error sendto():");
		exit(EXIT_FAILURE);
	}

/*		Envoie du packet TCP		*/
	close(sockfd);

/*
	struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
        }
    }

    freeifaddrs(ifap);
*/
}
