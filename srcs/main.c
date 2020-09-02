/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:12:17 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/01 22:56:46 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	init_t_nmap(t_nmap *nmap)
{
	ft_memset(nmap, 0, sizeof(nmap));
	nmap->ip = NULL;
	nmap->type = 0;
	nmap->ports = NULL;
	nmap->scan = NULL;
	nmap->threads = 0;
}

int		main(int argc, char **argv)
{
	t_nmap	nmap;

	init_t_nmap(&nmap);
	if (argc <= 1)
		print_help(&nmap);
	parsing(&nmap, argc, argv);

	//scan every host
	ft_nmap(&nmap);

	exit_nmap(&nmap, EXIT_SUCCESS);
	return (0);
}
