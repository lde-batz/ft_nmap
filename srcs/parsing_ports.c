/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing_ports.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/16 11:09:28 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/04 15:48:26 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void		*free_num_ports(t_num_ports *num_ports)
{
	t_num_ports	*tmp;

	while (num_ports)
	{
		tmp = num_ports;
		num_ports = num_ports->next;
		free(tmp);
	}
	return (NULL);
}

int			find_span_port(char *str)
{
	size_t i;
	size_t nb;

	i = 0;
	nb = 0;
	while (str[i] >= '0' && str[i] <= '9')
		i++;
	if (str[i++] != '-')
		return (0);
	while (str[i] >= '0' && str[i] <= '9')
		nb = nb * 10 + (str[i++] - '0');
	if (str[i])
		return (0);
	return (nb);
}

t_num_ports	*new_num_port(t_num_ports *num_ports, int nb1, int nb2)
{
	t_num_ports	*new;

	if (!(new = (t_num_ports*)malloc(sizeof(t_num_ports))))
		return (num_ports);
	new->nb1 = nb1;
	new->nb2 = nb2;
	new->next = num_ports;
	return (new);
}

t_num_ports	*get_all_ports(char *str)
{
	t_num_ports	*num_ports;
	int			i;
	int			nb1;
	int			nb2;
	char		**str_split;

	num_ports = NULL;
	i = -1;
	str_split = ft_strsplit(str, ',');
	while (str_split[++i])
	{
		nb1 = 0;
		nb2 = 0;
		if (ft_atoi_strict(str_split[i], &nb1, 0))
			num_ports = new_num_port(num_ports, nb1, nb1);
		else
		{
			if ((nb2 = find_span_port(str_split[i])))
				num_ports = new_num_port(num_ports, nb1, nb2);
			if (nb2 < 1 || nb1 > nb2)
			{
				free_double_char(str_split);
				return (free_num_ports(num_ports));
			}
		}
		if (nb1 < 1)
		{
			free_double_char(str_split);
			return (free_num_ports(num_ports));
		}
	}
	free_double_char(str_split);
	return (num_ports);
}

int			cnt_nb_ports(t_num_ports *num_ports)
{
	int			i;
	int			new_num;
	int			nb_ports;
	t_num_ports	*tmp;

	nb_ports = 0;
	while (num_ports)
	{
		i = num_ports->nb1 - 1;
		while (++i <= num_ports->nb2)
		{
			new_num = 1;
			tmp = num_ports->next;
			while (tmp)
			{
				if (i >= tmp->nb1 && i <= tmp->nb2)
					new_num = 0;
				tmp = tmp->next;
			}
			nb_ports += new_num;
		}
		num_ports = num_ports->next;
	}
	return (nb_ports);
}

void		set_nmap_ports(t_nmap *nmap, t_num_ports *num_ports)
{
	int			i;
	int			new_num;
	int			nb_ports;
	t_num_ports	*tmp;

	nb_ports = 0;
	while (num_ports)
	{
		i = num_ports->nb1 - 1;
		while (++i <= num_ports->nb2)
		{
			new_num = 1;
			tmp = num_ports->next;
			while (tmp)
			{
				if (i >= tmp->nb1 && i <= tmp->nb2)
					new_num = 0;
				tmp = tmp->next;
			}
			if (new_num)
				nmap->ports[nb_ports++] = i;
		}
		num_ports = num_ports->next;
	}
	nmap->ports[nb_ports] = 0;
}

void		sort_nmap_ports(t_nmap *nmap)
{
	int	i;
	int	j;
	int	swap;

	i = 0;
	while (nmap->ports[++i])
	{
		j = -1;
		while (nmap->ports[++j + i])
		{
			if (nmap->ports[j] > nmap->ports[j + 1])
			{
				swap = nmap->ports[j];
				nmap->ports[j] = nmap->ports[j + 1];
				nmap->ports[j + 1] = swap;
			}
		}
	}
}

void		parsing_ports(t_nmap *nmap, char *ports)
{
	int			nb_ports;
	t_num_ports	*num_ports;

	if ((num_ports = get_all_ports(ports)))
	{
		if ((nb_ports = cnt_nb_ports(num_ports)) > 1024)
		{
			free_num_ports(num_ports);
			printf("Bad argurment --ports '%s' : number of ports 1024 MAX\n\n", ports);
			print_help(nmap);
		}
		if (!(nmap->ports = (uint16_t*)malloc(sizeof(uint16_t) * (nb_ports + 1))))
		{
			free_num_ports(num_ports);
			exit_nmap(nmap, EXIT_FAILURE);
		}
		set_nmap_ports(nmap, num_ports);
		sort_nmap_ports(nmap);
		free_num_ports(num_ports);
	}
	else
	{
		printf("Bad argurment --ports '%s'\n\n", ports);
		print_help(nmap);
	}
}
