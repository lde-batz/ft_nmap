/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   report_conclusion.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/08 10:04:44 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/11 15:19:14 by lde-batz         ###   ########.fr       */
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
	if (type & SCAN_CON && rep->con_status)
	{
		rep->conclusion = rep->con_status;
		return ;
	}
	if (type & SCAN_ACK && rep->ack_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->ack_status;
		else if (rep->conclusion & rep->ack_status)
			rep->conclusion = rep->conclusion & rep->ack_status;
		else
			rep->conclusion = PORT_CLOSED;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_NULL && rep->null_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->null_status;
		else if (rep->conclusion & rep->null_status)
			rep->conclusion = rep->conclusion & rep->null_status;
		else
			rep->conclusion = PORT_CLOSED;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_FIN && rep->fin_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->fin_status;
		else if (rep->conclusion & rep->fin_status)
			rep->conclusion = rep->conclusion & rep->fin_status;
		else
			rep->conclusion = PORT_CLOSED;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_XMAS && rep->xmas_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->xmas_status;
		else if (rep->conclusion & rep->xmas_status)
			rep->conclusion = rep->conclusion & rep->xmas_status;
		else
			rep->conclusion = PORT_CLOSED;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_UDP && rep->udp_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->udp_status;
		else if (rep->conclusion & rep->udp_status)
			rep->conclusion = rep->conclusion & rep->udp_status;
		else
			rep->conclusion = PORT_CLOSED;
	}
	if (rep->conclusion & PORT_CLOSED)
		return ;
	if (type & SCAN_MAI && rep->mai_status)
	{
		if (!rep->conclusion)
			rep->conclusion = rep->mai_status;
		else if (rep->conclusion & rep->mai_status)
			rep->conclusion = rep->conclusion & rep->mai_status;
		else
			rep->conclusion = PORT_CLOSED;
	}
}

void	set_conclusion_report(t_scan *scan)
{
	t_scan_report *rep = scan->report;
	t_scan_report *before = scan->report;
	t_scan_report *last_open = NULL;

	scan->report_open = NULL;
	while (rep != NULL)
	{
		if (!conclusion_one_scan(scan->type, rep))
			conclusion_many_scans(scan->type, rep);

		if (rep->conclusion & PORT_OPEN)
		{
			if (scan->report_open == NULL)
			{
				scan->report_open = rep;
				last_open = rep;
			}
			else
			{
				last_open->next = rep;
				last_open = rep;
			}
			if (rep == scan->report)
			{
				scan->report = rep->next;
				before = scan->report;
				rep->next = NULL;
				rep = scan->report;
			}
			else
			{
				before->next = rep->next;
				rep->next = NULL;
				rep = before->next;
			}
		}
		else
		{
			if (rep != scan->report)
				before = before->next;
			rep = rep->next;
		}
	}
}
