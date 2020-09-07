/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decoder.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/03 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/07 12:17:42 by seb              ###   ########.fr       */
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

/*	dprintf(2, "\nScan: %u\n", thread_data->current_type);
	dprintf(2, "Sent SEQ: %u\n", ntohl(thread_data->seq) + 1);
	dprintf(2, "Received ACK %u\n", ntohl(tcp_header->th_ack));*/
	
	if (ntohl(thread_data->seq) + 1 == ntohl(tcp_header->th_ack))
	{
		thread_data->mismatch = 0;
		for (uint8_t shift = 1, index = 0; shift < 64 && index < 5; shift = shift << 1, index++)
			if (thread_data->current_type == shift)
				handlers[index](thread_data, resp_flags, -1);
	}
	else
	{
		thread_data->mismatch = 1;
		//dprintf(2, "Seq/Ack mismatch!\n");
	}
	
	return (0);
}

uint32_t	decode_udp_packet(const uint8_t *header_start)
{
	(void)header_start;
    printf("\t\t{{  Layer 4 :::: UDP Header  }}\n");
	return (0);
}

uint32_t	decode_icmp_packet(t_thread_data *thread_data, const uint8_t *header_start)
{
	struct icmphdr   		*icmp_header;

	icmp_header = (struct icmphdr *) header_start;
/*
	printf("\t\t{{ Layer 3 ::: ICMP Header }}\n");
	printf("\t\t{ ICMP Type: %u\t", icmp_header->type);
	printf("ICMP Code: %u\t\n\n", icmp_header->code);
*/
	if (icmp_header->type == 3) /* Unreachable */
	{
		uint8_t		(*handlers[5])(t_thread_data *, uint8_t, int8_t) = { &syn_handler,
					&ack_handler, &null_handler, &fin_handler, &xmas_handler};

		for (uint8_t shift = 1, index = 0; shift < 64 && index < 5; shift = shift << 1, index++)
			if (thread_data->current_type == shift)
				handlers[index](thread_data, 0, icmp_header->type);
	}
	return (0);
}

uint32_t	decode_ip_packet(const uint8_t *header_start)
{
	const struct ip		*ip_header;

	ip_header = (const struct ip*) header_start;
//	printf("\t((  Layer 3 ::: IP Header  ))\n");

/*	printf("\t( Source: %s\t", inet_ntoa(*(struct in_addr*)&(ip_header->ip_src)));
	printf("Dest: %s )\n", inet_ntoa(*(struct in_addr*)&(ip_header->ip_dst)));
	printf("\t( Type: %u\t", (uint32_t) ip_header->ip_p);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
*/
	return ((uint32_t) ip_header->ip_p);
}