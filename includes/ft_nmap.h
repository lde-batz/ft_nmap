/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 16:22:45 by lde-batz          #+#    #+#             */
/*   Updated: 2020/08/18 11:30:01 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include "libft.h"

# include <stdio.h>
# include <fcntl.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>

# define SCAN_SYN 0x20
# define SCAN_NULL 0x10
# define SCAN_ACK 0x08
# define SCAN_FIN 0x04
# define SCAN_XMAS 0x02
# define SCAN_UDP 0x01

typedef struct	s_num_ports
{
	int					nb1;
	int					nb2;
	struct s_num_ports	*next;
}				t_num_ports;

typedef struct	s_hostname_file
{
	char					*hostname;
	char					*ip;
	struct s_hostname_file	*next;
}				t_hostname_file;

typedef struct	s_nmap
{
	char	**ip;
	char	**hostname;
	int		ip_len;

	char	scans;
	int		*ports;
	int		theads;
}				t_nmap;


void			print_help(t_nmap *nmap);

void			parsing(t_nmap *nmap, int argc, char **argv);

void			parsing_ports(t_nmap *nmap, char *ports);

void			parsing_file(t_nmap *nmap, char *file);

void			exit_nmap(t_nmap *nmap, int exit_opt);

void			free_double_char(char **str);
int				ft_atoi_strict(char *str, int *nb, int freeit);

#endif
