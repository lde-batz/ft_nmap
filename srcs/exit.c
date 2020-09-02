/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exit.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/16 14:39:55 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/01 11:13:08 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	exit_nmap(t_nmap *nmap, int exit_opt)
{
//	int	i;

//	i = -1;
	if (nmap)
	{/*
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
		}*/
	}
	exit(exit_opt);
}
