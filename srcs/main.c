/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:12:17 by lde-batz          #+#    #+#             */
/*   Updated: 2020/08/16 19:34:39 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	init_t_nmap(t_nmap *nmap)
{
	ft_bzero(nmap, sizeof(nmap));
	nmap->ip = NULL;
	nmap->ports = NULL;
}

int		main(int argc, char **argv)
{
	t_nmap	nmap;

	init_t_nmap(&nmap);
	if (argc <= 1)
		print_help(&nmap);
	parsing(&nmap, argc, argv);
	exit_nmap(&nmap, EXIT_SUCCESS);
	return (0);
}
