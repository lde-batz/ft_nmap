/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exit.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/16 14:39:55 by lde-batz          #+#    #+#             */
/*   Updated: 2020/08/18 12:21:38 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	exit_nmap(t_nmap *nmap, int exit_opt)
{
	int	i;

	i = -1;
	if (nmap->ports)
		free(nmap->ports);
	if (nmap->hostname)
	{
		while (nmap->hostname[++i])
			free(nmap->hostname[i]);
		free(nmap->hostname);
	}
	if (nmap->ip)
	{
		i = -1;
		while (nmap->ip[++i])
			free(nmap->ip[i]);
		free(nmap->ip);
	}
	exit(exit_opt);
}
