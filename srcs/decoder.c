/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decoder.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/03 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/03 17:12:07 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
/*
uint32_t	decode_icmp_packet(const uint8_t *header_start)
{
	uint32_t					header_size;
	const struct icmp   	*icmp_header;

	icmp_header = (const struct icmp_hdr *) header_start;
	printf("\t\t{{ Layer 3 ::: ICMP Header }}\n");
	printf("\t\t{ ICMP Type: %u\t", icmp_header->icmp_type);
	printf("ICMP Code: %u\t\n\n", icmp_header->icmp_code);
}
*/
static void        interp_flags(uint8_t flags, uint8_t type)
{
    dprintf("Scan type: %d.\n", type);
    if (type & )
    dprintf("Flags: ");
    if (flags & TH_FIN)
        printf("FIN ");
    if (flags & TH_SYN)
        printf("SYN ");
    if (flags & TH_RST)
        printf("RST ");
    if (flags & TH_PUSH)
        printf("PUSH ");
    if (flags & TH_ACK)
        printf("ACK ");
    if (flags & TH_URG)
        printf("URG ");
    printf("\n");
}

uint8_t	decode_tcp_packet(t_thread_data *thread_data, const uint8_t *header_start)
{
    uint32_t            header_size;
	const struct tcphdr *tcp_header;

    tcp_header = (const struct tcphdr*)header_start;
    header_size = 4 * tcp_header->th_off;
    
    printf("\t\t{{  Layer 4 :::: TCP Header  }}\n");
    printf("\t\t{  Src Port: %hu\t", ntohs(tcp_header->th_sport));
    printf("Dst Port: %hu }\n", ntohs(tcp_header->th_dport));
    printf("\t\t{  Seq #: %u\t Ack #: %u }\n", ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack));
    printf("\t\t{ Header size: %u\tFlags: ", header_size);
    return (tcp_header->th_flags);
}

uint32_t	decode_udp_packet(const uint8_t *header_start)
{
	(void)header_start;
	printf("Detected UDP protocol\n\n");
    return (0);
}

uint32_t	decode_ip_packet(const uint8_t *header_start)
{
	const struct ip		*ip_header;

	ip_header = (const struct ip*) header_start;
	printf("\t((  Layer 3 ::: IP Header  ))\n");

	printf("\t( Source: %s\t", inet_ntoa(*(struct in_addr*)&(ip_header->ip_src)));
	printf("Dest: %s )\n", inet_ntoa(*(struct in_addr*)&(ip_header->ip_dst)));
	printf("\t( Type: %u\t", (uint32_t) ip_header->ip_p);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
	return ((uint32_t) ip_header->ip_p);
}