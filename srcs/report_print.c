/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   report_print.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/07 16:39:04 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/14 15:01:51 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

char *service_to_str(t_nmap *nmap, uint16_t port)
{
	if (port <= 995)
		return (nmap->service_name[port]);
	return ("Unassigned");
}

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
		return ("OPEN|FILTERED");
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

void	print_results(uint8_t type, t_scan_report *rep)
{
	uint8_t	scan_by_line = 0;
	char	print_scans[48] = "";

	if (type & SCAN_SYN)
	{
		sprintf(print_scans, "SYN(%s) ", status_to_str(rep->syn_status));
		scan_by_line++;
	}
	if (type & SCAN_NULL)
	{
		sprintf(print_scans, "%sNULL(%s) ", print_scans, status_to_str(rep->null_status));
		scan_by_line++;
	}
	if (type & SCAN_FIN)
	{
		if (scan_by_line >= 2)
		{
			printf("%s\n%-32s", print_scans, "");
			scan_by_line = 0;
			sprintf(print_scans, "");
		}
		sprintf(print_scans, "%sFIN(%s) ", print_scans, status_to_str(rep->fin_status));
		scan_by_line++;
	}
	if (type & SCAN_XMAS)
	{
		if (scan_by_line >= 2)
		{
			printf("%s\n%-32s", print_scans, "");
			scan_by_line = 0;
			sprintf(print_scans, "");
		}
		sprintf(print_scans, "%sXMAS(%s) ", print_scans, status_to_str(rep->xmas_status));
		scan_by_line++;
	}
	if (type & SCAN_ACK)
	{
		if (scan_by_line >= 2)
		{
			printf("%s\n%-32s", print_scans, "");
			scan_by_line = 0;
			sprintf(print_scans, "");
		}
		sprintf(print_scans, "%sACK(%s) ", print_scans, status_to_str(rep->ack_status));
		scan_by_line++;
	}
	if (type & SCAN_UDP)
	{
		if (scan_by_line >= 2)
		{
			printf("%s\n%-32s", print_scans, "");
			scan_by_line = 0;
			sprintf(print_scans, "");
		}
		sprintf(print_scans, "%sUDP(%s) ", print_scans, status_to_str(rep->udp_status));
		scan_by_line++;
	}
	if (type & SCAN_CON)
	{
		if (scan_by_line >= 2)
		{
			printf("%s\n%-32s", print_scans, "");
			scan_by_line = 0;
			sprintf(print_scans, "");
		}
		sprintf(print_scans, "%sCON(%s) ", print_scans, status_to_str(rep->con_status));
		scan_by_line++;
	}
	if (type & SCAN_MAI)
	{
		if (scan_by_line >= 2)
		{
			printf("%s\n%-32s", print_scans, "");
			scan_by_line = 0;
			sprintf(print_scans, "");
		}
		sprintf(print_scans, "%sMAI(%s)", print_scans, status_to_str(rep->mai_status));
		scan_by_line++;
	}
	printf("%-40s", print_scans);
}
void	show_report(t_scan *scan, t_nmap *nmap)
{
	char	*str_port;
	
	scan->report = sort_report(scan->report);
	set_conclusion_report(scan);
	if (scan->report_open != NULL)
	{
		printf("\n");
		printf("Open ports:\n");
		printf("Port\tService Name\t\tResults\t\t\t\t\tConclusion\n");
		printf("-----------------------------------------------------------------------------------------------\n");
	}
	for (t_scan_report *rep_open = scan->report_open; rep_open != NULL; rep_open = rep_open->next)
	{
		str_port = ft_itoa(rep_open->portnumber);
		printf("%-8.8s%-24.24s", str_port, service_to_str(nmap, rep_open->portnumber));
		print_results(scan->type, rep_open);
		printf("%s\n", status_to_str(rep_open->conclusion));
		free(str_port);
	}
	if (scan->report != NULL)
	{
		printf("\n");
		printf("Closed/Filtered/Unfiltered ports:\n");
		printf("Port\tService Name\t\tResults\t\t\t\tConclusion\n");
		printf("-----------------------------------------------------------------------------------------------\n");
	}
	for (t_scan_report *rep = scan->report; rep != NULL; rep = rep->next)
	{
		str_port = ft_itoa(rep->portnumber);
		printf("%-8.8s%-24.24s", str_port, service_to_str(nmap, rep->portnumber));
		print_results(scan->type, rep);
		printf("%s\n", status_to_str(rep->conclusion));
		free(str_port);
	}
}
