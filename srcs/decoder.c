/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decoder.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/03 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/09 22:04:23 by seb              ###   ########.fr       */
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

	if (ntohl(thread_data->seq) + 1 == ntohl(tcp_header->th_ack))
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

uint32_t	decode_icmp_packet(t_thread_data *thread_data, const uint8_t *buffer)
{
    struct iphdr	*iph;
	struct icmphdr	*icmph;
	struct udphdr	*udphdr;
	struct tcphdr	*tcph;
	uint32_t		iphdrlen,header_size;

	uint8_t		(*tcp_handlers[5])(t_thread_data *, uint8_t, int8_t) = { &syn_handler,
					&ack_handler, &null_handler, &fin_handler, &xmas_handler};
	
	iph = (struct iphdr *)(buffer  + ETHER_HDR_LEN);
    iphdrlen = iph->ihl * 4;
    icmph = (struct icmphdr *)(buffer + iphdrlen  + ETHER_HDR_LEN);
	thread_data->mismatch = 0;
	if (icmph->type == 3)
	{
		header_size =  ETHER_HDR_LEN + iphdrlen + sizeof(icmph);
		iph = (struct iphdr *)(buffer + header_size);
		iphdrlen = iph->ihl * 4;
		switch ((uint32_t)iph->protocol)
		{
			case UDP_CODE:
				udphdr = (struct udphdr *)(buffer + header_size + sizeof(struct iphdr));
				
				if (thread_data->current_type == SCAN_UDP
					&& thread_data->current_port == ntohs(udphdr->dest))
				{
				//	dprintf(2, "port %d got %d port RESPONSE\n", thread_data->current_port, ntohs(udphdr->dest));
					thread_data->mismatch = 0;
					udp_handler(thread_data, 42, icmph->code);
				}
				else
				{
					thread_data->mismatch = 1;
					for (t_scan_report *sr = g_scan->report; sr != NULL; sr = sr->next)
					{
						if (sr->portnumber == ntohs(udphdr->dest))
						{
							sr->udp_mismatch = 1;
							if (icmph->code == 3)
								sr->udp_status = PORT_CLOSED;
							else
								sr->udp_status = PORT_FILTERED;
							break ;
						}
					}

					//dprintf(2, "port %d got %d port MISMATCH\n", thread_data->current_port, ntohs(udphdr->dest));
				}
				break ;

			case TCP_CODE:
				tcph = (struct tcphdr *)(buffer + header_size + sizeof(struct iphdr));
				if (thread_data->current_type != SCAN_UDP
					&& thread_data->current_port == ntohs(tcph->th_dport))
				{
					thread_data->mismatch = 0;
					for (uint8_t shift = 1, index = 0; shift < 64 && index < 6; shift = shift << 1, index++)
						if (thread_data->current_type == shift)
							tcp_handlers[index](thread_data, 42, icmph->code);
				}
				else
					thread_data->mismatch = 1;
				break ;

			default :
				break ;
		}
	}
	return (0);
}

uint32_t	decode_ip_packet(const uint8_t *header_start)
{
	const struct ip		*ip_header;

	ip_header = (const struct ip*) header_start;
	return ((uint32_t) ip_header->ip_p);
}