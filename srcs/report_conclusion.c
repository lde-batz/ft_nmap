/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   report_conclusion.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/08 10:04:44 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/08 10:55:41 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int		conclusion_one_scan(uint8_t type, t_scan_report *rep)
{
	if (!(type ^ SCAN_SYN))
		rep->conclusion = rep->syn_status;
	else if (!(type ^ SCAN_ACK))
		rep->conclusion = rep->ack_status;
	else if (!(type ^ SCAN_NULL))
		rep->conclusion = rep->null_status;
	else if (!(type ^ SCAN_FIN))
		rep->conclusion = rep->fin_status;
	else if (!(type ^ SCAN_XMAS))
		rep->conclusion = rep->xmas_status;
	else if (!(type ^ SCAN_UDP))
		rep->conclusion = rep->udp_status;
	else if (!(type ^ SCAN_CON))
		rep->conclusion = rep->con_status;
	else if (!(type ^ SCAN_MAI))
		rep->conclusion = rep->mai_status;
	else
		return (0);
	return (1);
}

void	conclusion_many_scans(uint8_t type, t_scan_report *rep)
{
	if (type & SCAN_SYN && rep->syn_status)
	{
		rep->conclusion = rep->syn_status;
		if (rep->syn_status == PORT_OPEN)
			return ;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_ACK && rep->ack_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->ack_status;
		else if (rep->conclusion != rep->ack_status)
			rep->conclusion = PORT_CLOSED;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_NULL && rep->null_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->null_status;
		else if (rep->conclusion != rep->null_status)
		{
			if (rep->conclusion ^ PORT_FILTERED || rep->null_status ^ PORT_FILTERED)
				rep->conclusion = PORT_CLOSED;
		}
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_FIN && rep->fin_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->fin_status;
		else if (rep->conclusion != rep->fin_status)
		{
			if (!(rep->fin_status ^ PORT_FILTERED) && rep->conclusion & PORT_FILTERED)
				rep->conclusion = PORT_FILTERED;
			else if (!(rep->conclusion ^ PORT_FILTERED) && rep->fin_status & PORT_FILTERED)
				rep->conclusion = PORT_FILTERED;
			else
				rep->conclusion = PORT_CLOSED;
		}
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_XMAS && rep->xmas_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->xmas_status;
		else if (rep->conclusion != rep->xmas_status)
		{
			if (!(rep->xmas_status ^ PORT_FILTERED) && rep->conclusion & PORT_FILTERED)
				rep->conclusion = PORT_FILTERED;
			else if (!(rep->conclusion ^ PORT_FILTERED) && rep->xmas_status & PORT_FILTERED)
				rep->conclusion = PORT_FILTERED;
			else
				rep->conclusion = PORT_CLOSED;
		}
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_UDP && rep->udp_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->udp_status;
		else if (rep->conclusion != rep->udp_status)
		{
			if (!(rep->udp_status ^ PORT_FILTERED) && rep->conclusion & PORT_FILTERED)
				rep->conclusion = PORT_FILTERED;
			else if (!(rep->conclusion ^ PORT_FILTERED) && rep->udp_status & PORT_FILTERED)
				rep->conclusion = PORT_FILTERED;
			else
				rep->conclusion = PORT_CLOSED;
		}
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
}


void	set_conclusion_report(t_scan *scan)
{
	for (t_scan_report *rep = scan->report; rep != NULL; rep = rep->next)
	{
		if (!conclusion_one_scan(scan->type, rep))
			conclusion_many_scans(scan->type, rep);
	}
}
