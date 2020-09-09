/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:32:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/09 20:41:52 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

static void    print_config(t_nmap *nmap)
{
	dprintf(STDOUT_FILENO, "Scan configuration:\n");
	dprintf(STDOUT_FILENO, "Scan to perform: %s%s%s%s%s%s\n",
		(nmap->type & SCAN_SYN) ?  "SYN " : "",
		(nmap->type & SCAN_NULL) ?  "NULL " : "",
		(nmap->type & SCAN_ACK) ?  "ACK " : "",
		(nmap->type & SCAN_FIN) ?  "FIN " : "",
		(nmap->type & SCAN_XMAS) ?  "XMAS " : "",
		(nmap->type & SCAN_UDP) ?  "UDP " : "");
	dprintf(STDOUT_FILENO, "Amount of threads: %d\n", nmap->threads);
}

void	print_scanning(void)
{
	g_scan->scanning = 1;
	dprintf(STDOUT_FILENO, "Scanning...\n");
	alarm(1);
}

void    ft_nmap(t_nmap *nmap)
{
	t_thread_data   *pseudo_thread_data;
	t_scan			*scan;

	print_config(nmap);
	build_scanlist(nmap);
	for (scan = nmap->scan; scan != NULL; scan = scan->next)
	{
		g_scan = scan;
		print_scanning();
		
		if (nmap->threads == 0)		/* Aucun thread */
		{
			pseudo_thread_data = allocate_thread_data(scan, 0, 0);
			scan_callback((void*)pseudo_thread_data);
			free_thread_data(pseudo_thread_data);
		}
		else						/* Thread >= 1 */
			dispatch_threads(nmap, scan);

		g_scan->scanning = 0;
		dprintf(STDOUT_FILENO, "\nScan for %s finished\n", scan->ip);
		
		show_report(scan);
		free_reports(scan);
		free_threads_data(scan);
	}
	free_scanlist(nmap);
}