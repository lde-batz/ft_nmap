/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:12:17 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/15 15:17:25 by lde-batz         ###   ########.fr       */
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

uint8_t	wait_connect(struct timeval *tv, int sec)
{
	int				tv_usec;
	int				time_usec;
	struct timeval	time;

	gettimeofday(&time, NULL);
	tv_usec = tv->tv_sec * 1000000 + tv->tv_usec;
	time_usec = time.tv_sec * 1000000 + time.tv_usec;
	if (time_usec - tv_usec > sec * 1000000)
		return (0);
	else
		return (1);
}

void	send_tcp_packet_connect(t_thread_data *data, uint16_t port)
{
	int					sockfd;
	struct sockaddr_in	daddr;
	struct timeval		tv;

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
	
/*		Envoie du packet TCP		*/
	pthread_mutex_lock(&(g_scan->mutex));
	fcntl(sockfd, F_SETFL, O_NONBLOCK);
	gettimeofday(&tv, NULL);
	while (wait_connect(&tv, 1))
	{
		if (connect(sockfd, (struct sockaddr *)&daddr, sizeof(daddr)) == 0)
		{
			data->report->con_status = PORT_OPEN;
			break;
		}
		else
			data->report->con_status = PORT_CLOSED;
	}
	close(sockfd);
	pthread_mutex_unlock(&(g_scan->mutex));
}

int		send_packet(t_thread_data *data, uint8_t type, uint16_t port)
{
	if (type & SCAN_UDP)
		send_udp_packet(data, port);
	else if (type & SCAN_CON)
		send_tcp_packet_connect(data, port);
	else
		send_tcp_packet(data, type, port);
	return (1);
}
