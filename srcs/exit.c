/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exit.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/16 14:39:55 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/14 14:14:04 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	free_reports(t_scan *scan)
{
	t_scan_report *rp = scan->report;
	t_scan_report *tmp;
	
	while (rp != NULL)
	{
		tmp = rp;
		rp = rp->next;
		free(tmp);
	}
	
	rp = scan->report_open;
	while (rp != NULL)
	{
		tmp = rp;
		rp = rp->next;
		free(tmp);
	}
}

void	free_thread_data(t_thread_data *dt)
{
	free(dt->port_list);
	free(dt);
}

void	free_scanlist(t_nmap *nmap)
{
	for (t_scan *tmp = NULL, *sc = nmap->scan; sc != NULL; )
	{
		tmp = sc;
		sc = sc->next;
		free(tmp);
	}
	
}

void	free_threads_data(t_scan *sc)
{
	for (t_thread_data *tmp = NULL, *td = sc->threads; td != NULL; )
	{
		tmp = td;
		td = td->next;
		ft_strdel(&tmp->src_ipv4);
		free(tmp->port_list);
		free(tmp);
	}
}

void	exit_nmap(t_nmap *nmap, int exit_opt)
{
	int	i;
	t_scan	*free_scan;

	if (nmap)
	{
		if (nmap->ports)
			free(nmap->ports);
		if (nmap->hostname)
		{
			i = 0;
			while (nmap->hostname[i])
			{
				free(nmap->hostname[i]);
				++i;
			}
			free(nmap->hostname);
		}
		if (nmap->ip)
		{
			i = 0;
			while (nmap->ip[i])
			{
				free(nmap->ip[i]);
				++i;
			}
			free(nmap->ip);
		}
		if (nmap->service_name)
			free(nmap->service_name);
		while (nmap->scan)
		{
			free_scan = nmap->scan;
			nmap->scan = nmap->scan->next;
			free(free_scan);
		}
	}
	exit(exit_opt);
}
