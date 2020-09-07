/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   help.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 16:29:09 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/07 10:58:55 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	print_help(t_nmap *nmap)
{
	printf("Help Sreen\n\n");
	printf("Usage:\n");
	printf("ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --ip ADRESSE IP [--speedup [NOMBRE]] [--scan [TYPE]]\n");
	printf("or\n");
	printf("ft_nmap [--help] [--ports [NOMBRE/PLAGE]] --file FICHIER [--speedup [NOMBRE]] [--scan [TYPE]]\n\n");
	printf(" --help		Print this help screen\n");
	printf(" --ports	[1024 max]ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
	printf(" --ip		ip addresses to scan in dot format\n");
	printf(" --file		File name containing IP addresses to scan,\n");
	printf(" --speedup	[250 max] number of parallel threads to use\n");
	printf(" --scan		SYN/NULL/FIN/XMAS/ACK/UDP/CON/MAI\n");
	exit_nmap(nmap, EXIT_FAILURE);
}
