/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing_file.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/17 20:59:08 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/10 11:50:47 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void			free_hostname_file(t_hostname_file *l_hostname)
{
	t_hostname_file	*tmp;

	while (l_hostname)
	{
		tmp = l_hostname;
		l_hostname = l_hostname->next;
		free(tmp);
	}
}

t_hostname_file	*new_hostname_file(t_nmap *nmap, t_hostname_file *l_hostname, char *hostname, char *ip)
{
	t_hostname_file	*new;

	if (!(new = (t_hostname_file*)malloc(sizeof(t_hostname_file))))
	{
		perror("malloc()");
		free_hostname_file(l_hostname);
		exit_nmap(nmap, EXIT_FAILURE);
	}
	new->hostname = hostname;
	new->ip = ip;
	new->next = l_hostname;
	return (new);
}

t_hostname_file	*get_ip_by_hostname(t_nmap *nmap, char *line, t_hostname_file *l_hostname, int *len)
{
	char				host[INET_ADDRSTRLEN];
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct sockaddr_in	*host_sockaddr;

	ft_memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	if (getaddrinfo(line, NULL, &hints, &res) != 0)
		return (l_hostname);
	host_sockaddr = (struct sockaddr_in *)res->ai_addr;
	if (inet_ntop(AF_INET, &host_sockaddr->sin_addr, host, INET_ADDRSTRLEN)
																	== NULL)
	{
		freeaddrinfo(res);
		return (l_hostname);
	}
	*len = *len + 1;
	l_hostname = new_hostname_file(nmap, l_hostname, ft_strdup(line), ft_strdup(host));
	freeaddrinfo(res);
	return (l_hostname);
}

void		set_nmap_ip_hostname(t_nmap *nmap, t_hostname_file *l_hostname, int len)
{
	int	i;

	i = -1;
	nmap->ip = (char**)malloc(sizeof(char*) * (len + 1));
	nmap->hostname = (char**)malloc(sizeof(char*) * (len + 1));
	if (!nmap->ip || !nmap->hostname)
	{
		perror("malloc()");
		exit_nmap(nmap, EXIT_FAILURE);
	}
	while (++i < len && l_hostname)
	{
		nmap->ip[i] = l_hostname->ip;
		nmap->hostname[i] = l_hostname->hostname;
		l_hostname = l_hostname->next;
	}
	nmap->ip[len] = NULL;
	nmap->hostname[len] = NULL;
	nmap->ip_len = len;
}

void	parsing_file(t_nmap *nmap, char *file)
{
	int				fd;
	int				len;
	char			*line;
	t_hostname_file	*l_hostname;

	len = 0;
	fd = 0;
	l_hostname = NULL;
	if (!(ft_strcmp(file, "/dev/zero")) || (fd = open(file, O_RDONLY)) < 0)
	{
		printf("Bad argurment --file '%s'", file);
		exit_nmap(nmap, EXIT_FAILURE);
	}
	while (get_next_line(fd, &line))
	{
		l_hostname = get_ip_by_hostname(nmap, line, l_hostname, &len);
		free(line);
	}
	free(line);
	close(fd);
	if (l_hostname == NULL)
	{
		printf("Bad file '%s': it's empty or all hosts are bad", file);
		exit_nmap(nmap, EXIT_FAILURE);
	}
	set_nmap_ip_hostname(nmap, l_hostname, len);
	free_hostname_file(l_hostname);
}
