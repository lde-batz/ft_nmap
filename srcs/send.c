/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:12:17 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/05 12:59:39 by seb              ###   ########.fr       */
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

int		send_packet(char *device, t_thread_data *data, uint8_t type, uint16_t port)
{
	if (type & SCAN_UDP)
		send_udp_packet(data, port);
	else
		send_tcp_packet(device, data, type, port);
	return (1);
}
