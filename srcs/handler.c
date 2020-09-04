/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   handler.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/04 13:47:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/04 16:53:25 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

uint8_t     syn_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->syn_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->syn_status = PORT_FILTERED;
	else if (tcp_flags & TH_RST)
		thread_data->report->syn_status = PORT_CLOSED;
	else if (tcp_flags & TH_SYN && tcp_flags & TH_ACK)
		thread_data->report->syn_status = PORT_OPEN;
	else
		thread_data->report->syn_status = PORT_UNKNOWN;
	return (0);
}

uint8_t     ack_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->ack_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->ack_status = PORT_FILTERED;
	else if (tcp_flags & TH_RST)
		thread_data->report->ack_status = PORT_UNFILTERED;
	else
		thread_data->report->ack_status = PORT_UNKNOWN;
	return (0);
}

uint8_t     null_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->null_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->null_status = PORT_OPEN | PORT_FILTERED;
	else if (tcp_flags & TH_RST)
		thread_data->report->null_status = PORT_CLOSED;
	else
		thread_data->report->null_status = PORT_UNKNOWN;
	return (0);
}

uint8_t     fin_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->fin_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->fin_status = PORT_OPEN | PORT_FILTERED;
	else if (tcp_flags & TH_RST)
		thread_data->report->fin_status = PORT_CLOSED;
	else
		thread_data->report->fin_status = PORT_UNKNOWN;
	return (0);
}

uint8_t     xmas_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->xmas_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->xmas_status = PORT_OPEN | PORT_FILTERED;
	else if (tcp_flags & TH_RST)
		thread_data->report->xmas_status = PORT_CLOSED;
	else
		thread_data->report->xmas_status = PORT_UNKNOWN;
	return (0);
}

uint8_t     udp_handler()
{
	printf("UDP HANDLER\n");
	return (0);
}