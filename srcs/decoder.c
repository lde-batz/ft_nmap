/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decoder.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/03 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/07 18:25:07 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

uint8_t	decode_tcp_packet(t_thread_data *thread_data, const uint8_t *header_start)
{
	uint32_t            header_size;
	const struct tcphdr *tcp_header;
	uint8_t             resp_flags;
	
	uint8_t		(*handlers[5])(t_thread_data *, uint8_t, int8_t)= { &syn_handler, &ack_handler, &null_handler, &fin_handler, &xmas_handler};

	tcp_header = (const struct tcphdr*)header_start;
	header_size = 4 * tcp_header->th_off;
	resp_flags = tcp_header->th_flags;
	if (resp_flags & TH_RST || ntohl(thread_data->seq) + 1 == ntohl(tcp_header->th_ack))
	{
		thread_data->mismatch = 0;
		for (uint8_t shift = 1, index = 0; shift < 64 && index < 5; shift = shift << 1, index++)
			if (thread_data->current_type == shift)
				handlers[index](thread_data, resp_flags, -1);
	}
	else
		thread_data->mismatch = 1;
	return (0);
}

uint32_t	decode_udp_packet(t_thread_data *thread_data, const uint8_t *header_start)
{
	(void)header_start;
	thread_data->mismatch = 0;
	udp_handler(thread_data, 42, -1);
	return (0);
}

uint32_t	decode_icmp_packet(t_thread_data *thread_data, const uint8_t *header_start)
{
	struct icmphdr   		*icmp_header;
	
	thread_data->mismatch = 0;
	icmp_header = (struct icmphdr *) header_start;

/*	struct iphdr *iphdr = (struct iphdr*)(icmp_header + sizeof(struct icmphdr));
	struct udphdr *udph = (struct udphdr *)iphdr + sizeof(struct iphdr);
	dprintf(2, "(Port %d %d thread) Received icmp %d bytes message for port %d\n", thread_data->current_port, thread_data->current_type,
			udph->len ,udph->uh_dport);
*/	
	if (icmp_header->type == 3) /* Unreachable */
	{
		uint8_t		(*handlers[6])(t_thread_data *, uint8_t, int8_t) = { &syn_handler,
					&ack_handler, &null_handler, &fin_handler, &xmas_handler, &udp_handler};

		for (uint8_t shift = 1, index = 0; shift < 64 && index < 6; shift = shift << 1, index++)
			if (thread_data->current_type == shift)
				handlers[index](thread_data, 42, icmp_header->type);
	}
	return (0);
}

uint32_t	decode_ip_packet(const uint8_t *header_start)
{
	const struct ip		*ip_header;

	ip_header = (const struct ip*) header_start;
	return ((uint32_t) ip_header->ip_p);
}