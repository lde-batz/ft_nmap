/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send_udp.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/04 17:33:09 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/04 18:09:08 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	init_udphdr(struct udphdr *udph, uint16_t port)
{
	udph->uh_sport = htons(54321);
	udph->uh_dport = htons(port);
	printf("SIZE = %lu\n", sizeof(struct udphdr));
	udph->uh_ulen = sizeof(struct udphdr) / 4;
	udph->uh_sum = 0;
	udph->uh_sum = checksum((unsigned short *)&udph, sizeof(struct udphdr));
}

void	send_udp_packet(t_thread_data *data, uint16_t port)
{
	int					sockfd;
	struct sockaddr_in	daddr;

	/*		Initialisation du socket UDP		*/
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		printf("fuck!\n");
		perror("Error creating socket");
		exit(EXIT_FAILURE);
	}

/*		Initialisation adresse destination		*/
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(port);
	if (inet_pton(AF_INET, data->ipv4, &daddr.sin_addr) != 1)
	{
		perror("Error inet_pton:");
		exit(EXIT_FAILURE);
	}

/*		Envoie du packet UDP		*/
	if (sendto(sockfd, 0, 0, 0, (struct sockaddr *)&daddr, sizeof(daddr)) < 0)
	{
		perror("Error sendto():");
		exit(EXIT_FAILURE);
	}

/*		Envoie du packet UDP		*/
	close(sockfd);
}
