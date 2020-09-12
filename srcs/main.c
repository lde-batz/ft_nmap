/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:12:17 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/12 12:22:07 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	init_t_nmap(t_nmap *nmap)
{
	if (getuid() != 0)
	{
		dprintf(STDERR_FILENO, "Error: only root is permitted\n");
        exit(EXIT_FAILURE);
	}
	ft_memset(nmap, 0, sizeof(nmap));
	nmap->ip = NULL;
	nmap->type = 0;
	nmap->ports = NULL;
	nmap->scan = NULL;
	nmap->threads = 0;

/*		Initialisation signal		*/
	struct sigaction	act;

	ft_bzero(&act, sizeof(act));
	act.sa_sigaction = &sig_alarm;
	sigaction(SIGALRM, &act, NULL);

/*		Initialisation des noms de services		*/
	init_service_name(nmap);
}

int		main(int argc, char **argv)
{
	t_nmap	nmap;

	init_t_nmap(&nmap);
	if (argc <= 1)
		print_help(&nmap);
	parsing(&nmap, argc, argv);
	ft_nmap(&nmap);
	exit_nmap(&nmap, EXIT_SUCCESS);
	return (0);
}
