/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:32:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/03 15:52:30 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

static void    print_config(t_nmap *nmap)
{
	dprintf(STDERR_FILENO, "Scan configuration:\n");
	dprintf(STDERR_FILENO, "Scan to perform: %s%s%s%s%s%s\n",
		(nmap->type & SCAN_SYN) ?  "SYN " : "",
		(nmap->type & SCAN_NULL) ?  "NULL " : "",
		(nmap->type & SCAN_ACK) ?  "ACK " : "",
		(nmap->type & SCAN_FIN) ?  "FIN " : "",
		(nmap->type & SCAN_XMAS) ?  "XMAS " : "",
		(nmap->type & SCAN_UDP) ?  "UDP " : "");
	dprintf(STDERR_FILENO, "Amount of threads: %d\n", nmap->threads);
	dprintf(STDERR_FILENO, "Go for scan.\n");
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
		if (nmap->threads == 0)		/* Aucun thread */
		{
			/* Creation de la thread_data pour compatibilité avec le callback */
			pseudo_thread_data = allocate_thread_data(scan, 0, 0);
			scan_callback((void*)pseudo_thread_data);
		}
		else						/* Thread >= 1 */
		{
			dispatch_threads(nmap, scan);
		}
		dprintf(STDERR_FILENO, "Scan for %s finished\n", scan->ip);
	}
}