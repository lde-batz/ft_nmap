/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:12:17 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/06 20:27:44 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int		checksum(unsigned short	*buf, int len)
{
	unsigned int	sum;
	unsigned short	res;

	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		len -= 2;
	}
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	res = ~sum;
	return (res);
}

void	send_tcp_packet_connect(t_thread_data *data, uint16_t port)
{
	int					sockfd;
	struct sockaddr_in	daddr;

/*		Initialisation du socket TCP		*/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		perror("Error creating socket:");
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
	
	fcntl(sockfd, F_SETFL, O_NONBLOCK);

/*		Envoie du packet TCP		*/
	if (connect(sockfd, (struct sockaddr *)&daddr, sizeof(daddr)) == 0)
		printf("port: %i -> open\n", port);
	else
		printf("port: %i -> close\n", port);
	printf("suivant\n");
}

int		send_packet(t_thread_data *data, uint8_t type, uint16_t port)
{
	type = SCAN_CON;
	if (type & SCAN_UDP)
		send_udp_packet(data, port);
	else if (type & SCAN_CON)
		send_tcp_packet_connect(data, port);
	else
		send_tcp_packet(data, type, port);
	return (1);
}
