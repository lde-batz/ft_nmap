/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   report_print.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/07 16:39:04 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/08 11:33:57 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

char *status_to_str(uint8_t status)
{
	if (status == PORT_CLOSED)
		return ("CLOSED");
	else if (status == PORT_OPEN)
		return ("OPEN");
	else if (status == PORT_FILTERED)
		return ("FILTERED");
	else if (status == PORT_UNFILTERED)
		return ("UNFILTERED");
	else if (status & PORT_OPEN && status & PORT_FILTERED)
		return ("OPEN | FILTERED");
	else
	{
		return ("UNKNOWN");
	}
}

int				lst_report_len(t_scan_report *rep)
{
	int	len;

	len = 0;
	while (rep != NULL)
	{
		len++;
		rep = rep->next;
	}
	return (len);
}

t_scan_report	*sort_report(t_scan_report *rep)
{
	int				len;
	t_scan_report	*rep1;
	t_scan_report	*before;

	len = lst_report_len(rep);
	for (int i = 0; i < len - 1; i++)
	{
		rep1 = rep;
		before = rep;
		for (int j = 0; j < len - (i + 1); j++)
		{
			if (rep1->portnumber > rep1->next->portnumber)
			{
				if (rep1 != rep)
				{
					before->next = rep1->next;
					rep1->next = before->next->next;
					before->next->next = rep1;
					rep1 = before->next;
				}
				else
				{
					rep = rep1->next;
					rep1->next = rep->next;
					rep->next = rep1;
					rep1 = rep;
					before = rep;
				}
			}
			if (rep1 != rep)
				before = before->next;
			rep1 = rep1->next;
		}
	}
	return rep;
}

void	show_report(t_scan *scan)
{
	scan->report = sort_report(scan->report);
	set_conclusion_report(scan);
	printf("\n");
	printf("Port\tService Name\t\tResults\t\t\t\t\t\tConclusion\n");
	printf("-----------------------------------------------------------------------------------------------\n");
	for (t_scan_report *rep = scan->report; rep != NULL; rep = rep->next)
	{
		printf("- Port %d\t\tSYN(%s) ACK(%s) XMAS(%s)   CONCLUSION(%s)\n", rep->portnumber,
		status_to_str(rep->syn_status), status_to_str(rep->ack_status), status_to_str(rep->xmas_status),
		status_to_str(rep->conclusion));
	}
}
