/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   handler.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/04 13:47:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/15 14:53:47 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

uint8_t     syn_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->syn_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->syn_status = PORT_FILTERED;
	else if (tcp_flags & TH_SYN && tcp_flags & TH_ACK)
		thread_data->report->syn_status = PORT_OPEN;
	else if (tcp_flags & TH_RST)
		thread_data->report->syn_status = PORT_CLOSED;
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

uint8_t		mai_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code)
{
	if (icmp_code != -1)
		thread_data->report->mai_status = PORT_FILTERED;
	else if (tcp_flags == 0)
		thread_data->report->mai_status = PORT_OPEN | PORT_FILTERED;
	else if (tcp_flags & TH_RST)
		thread_data->report->mai_status = PORT_CLOSED;
	else
		thread_data->report->mai_status = PORT_UNKNOWN;
	return (0);
}

uint8_t     udp_handler(t_thread_data *thread_data, uint8_t udp, int8_t icmp_code)
{
	if (thread_data->report->udp_mismatch == 1)
		return (0);
	if (icmp_code != -1)
	{
		if (icmp_code == 3)
			thread_data->report->udp_status = PORT_CLOSED;
		else
			thread_data->report->udp_status = PORT_FILTERED;
	}
	else if (udp == 0 && icmp_code == -1)
		thread_data->report->udp_status = PORT_OPEN | PORT_FILTERED;
	else
		thread_data->report->udp_status = PORT_OPEN;
	return (0);
}