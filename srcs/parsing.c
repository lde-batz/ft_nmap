/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 16:54:06 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/12 17:12:15 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	parsing_ip(t_nmap *nmap, char *ip)
{
	char				host[INET_ADDRSTRLEN];
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct sockaddr_in	*host_sockaddr;

	ft_memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	if (getaddrinfo(ip, NULL, &hints, &res) != 0)
	{
		printf("Bad argurment --ip '%s' : name or service not known\n", ip);
		exit_nmap(nmap, EXIT_FAILURE);
	}
	host_sockaddr = (struct sockaddr_in *)res->ai_addr;
	if (inet_ntop(AF_INET, &host_sockaddr->sin_addr, host, INET_ADDRSTRLEN) == NULL)
	{
		freeaddrinfo(res);
		perror("inet_ntop()");
		exit_nmap(nmap, EXIT_FAILURE);
	}
	freeaddrinfo(res);
	nmap->ip = (char**)malloc(sizeof(char*)*2);
	nmap->hostname = (char**)malloc(sizeof(char*)*2);
	if (!nmap->ip || !nmap->hostname)
	{
		perror("malloc()");
		exit_nmap(nmap, EXIT_FAILURE);
	}
	nmap->hostname[0] = ft_strdup(ip);
	nmap->ip[0] = ft_strdup(host);
	nmap->ip_len = 1;
	nmap->ip[1] = NULL;
	nmap->hostname[1] = NULL;
}

void	parsing_speedup(t_nmap *nmap, char *speedup)
{
	if (!ft_atoi_strict(speedup, &nmap->threads, 0) || nmap->threads < 0 || nmap->threads > 250)
	{
		printf("Bad argurment --speedup '%s'\n\n", speedup);
		print_help(nmap);
	}
}

void	parsing_scan(t_nmap *nmap, char *scan)
{
	int		i;
	char	**scan_split;

	i = -1;
	scan_split = ft_strsplit(scan, '/');
	while (scan_split[++i])
	{
		if (ft_strcmp(scan_split[i], "SYN") == 0)
			nmap->type = nmap->type | SCAN_SYN;
		else if (ft_strcmp(scan_split[i], "NULL") == 0)
			nmap->type = nmap->type | SCAN_NULL;
		else if (ft_strcmp(scan_split[i], "ACK") == 0)
			nmap->type = nmap->type | SCAN_ACK;
		else if (ft_strcmp(scan_split[i], "FIN") == 0)
			nmap->type = nmap->type | SCAN_FIN;
		else if (ft_strcmp(scan_split[i], "XMAS") == 0)
			nmap->type = nmap->type | SCAN_XMAS;
		else if (ft_strcmp(scan_split[i], "UDP") == 0)
			nmap->type = nmap->type | SCAN_UDP;
		else if (ft_strcmp(scan_split[i], "CON") == 0)
			nmap->type = nmap->type | SCAN_CON;
		else if (ft_strcmp(scan_split[i], "MAI") == 0)
			nmap->type = nmap->type | SCAN_MAI;
		else
		{
			free_double_char(scan_split);
			printf("Bad argurment --scan '%s'\n\n", scan);
			print_help(nmap);
		}
	}
	free_double_char(scan_split);
}

void	parsing(t_nmap *nmap, int argc, char **argv)
{
	int	i;

	i = 0;
	while (++i < argc)
	{
		if (i + 1 < argc)
		{
			if (ft_strcmp(argv[i], "--ports") == 0)
				parsing_ports(nmap, argv[++i]);
			else if (ft_strcmp(argv[i], "--ip") == 0)
				parsing_ip(nmap, argv[++i]);
			else if (ft_strcmp(argv[i], "--file") == 0)
				parsing_file(nmap, argv[++i]);
			else if (ft_strcmp(argv[i], "--speedup") == 0)
				parsing_speedup(nmap, argv[++i]);
			else if (ft_strcmp(argv[i], "--scan") == 0)
				parsing_scan(nmap, argv[++i]);
			else
			{
				if (ft_strcmp(argv[i], "--help") != 0)
				printf("Bad option '%s' (argc %i)\n\n", argv[i], i);
				print_help(nmap);
			}
		}
		else
			print_help(nmap);
	}
	if(!nmap->ip_len)
		print_help(nmap);
	i = -1;
	
/*		si aucun scan spécifié -> tous les scans activés		*/
	if (nmap->type == 0)
		nmap->type = SCAN_DEF;

/*		si aucun port spécifié -> scanner les ports de 1 à 1024		*/
	if (nmap->ports == NULL)
	{
		if (!(nmap->ports = (uint16_t*)malloc(sizeof(uint16_t) * 1025)))
			exit_nmap(nmap, EXIT_FAILURE);
		for(i = -1; i < 1024; i++)
			nmap->ports[i] = i + 1;
		nmap->ports[i] = 0;
	}

}
