/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 16:22:45 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/02 17:49:31 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

# include "libft.h"

# include <pcap.h>
# include <pthread.h>

# include <stdio.h>
# include <unistd.h>
# include <fcntl.h>
# include <sys/types.h>
# include <sys/socket.h>

# include <netdb.h> // gethostbyname
# include <arpa/inet.h> // inet_ntoa
# include <netinet/ip.h> // ip header
# include <netinet/tcp.h> // tcp header
# include <netinet/udp.h> // udp header

#include <netinet/in.h>

#define ETHER_ADDR_LEN	6
#define ETHER_HDR_LEN	14

struct				ether_hdr
{
	unsigned char	ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char	ether_src_addr[ETHER_ADDR_LEN];
	unsigned short	ether_type;
};

#define ICMP_CODE	1
#define TCP_CODE	6
#define UDP_CODE	17

struct				ip_hdr
{
	unsigned char	ip_version_and_header_length;
	unsigned char	ip_tos;
	unsigned short	ip_len;
	unsigned short	ip_id;
	unsigned short	ip_frag_offset;
	unsigned char 	ip_ttl;
	unsigned char	ip_type;
	unsigned short	ip_checksum;
	unsigned int	ip_src_addr;
	unsigned int	ip_dst_addr;
};



# define SCAN_SYN	0x20
# define SCAN_NULL	0x10 
# define SCAN_ACK	0x08
# define SCAN_FIN	0x04
# define SCAN_XMAS	0x02
# define SCAN_UDP	0x01 

# define MAX_PORTS 1024

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

typedef struct s_scan_report
{
	uint16_t	portnumber;
	uint8_t		syn_status;
	uint8_t		ack_status;
	uint8_t		null_status;
	uint8_t		fin_status;
	uint8_t		xmas_status;
	uint8_t		udp_status;
	char		service_name[64];
	struct s_scan_report *next;
}				t_scan_report;

typedef struct	s_thread_data
{
	pthread_t			identifier;
	
	char				*hostname;
	char				*ipv4;

	struct sockaddr_in	*sin;

	uint16_t			*port_list;
	
	uint8_t				type;
	
	struct s_thread_data *next;
}				t_thread_data;

typedef struct s_scan
{
	char				*name;	
	char				*ip;	// 127.0.0.1

	uint8_t				type;	// SYN | ACK | FIN etc..
	uint16_t			*ports;

	t_scan_report		*report;

	int					threads_running;

	t_thread_data		*threads; // t
	
	pthread_mutex_t		mutex;
	struct s_scan		*next;
}				t_scan;

extern t_scan	*g_scan;

typedef struct	s_nmap
{
	char		**ip;
	char		**hostname;
	int			ip_len;
	char		type;
	uint16_t	*ports;
	int			threads;
	t_scan		*scan;
}				t_nmap;


void		ft_nmap(t_nmap *nmap);
void    	build_scanlist(t_nmap *nmap);

t_thread_data	*allocate_thread_data(t_scan *scan, uint16_t amount, uint16_t offset);
void			dispatch_threads(t_nmap *nmap, t_scan *scan);
void			*scan_callback(void *data);

char			*get_pcap_device(bpf_u_int32 *net, bpf_u_int32 *mask, char errbuf[1024]);
pcap_t			*open_pcap_device(char *device, char errbuf[1024]);
void			apply_pcap_filter(pcap_t *handle, bpf_u_int32 net);

uint16_t	get_portnb(uint16_t *ports);
uint16_t	ft_checksum();

//void		craft_packet();

int			portscan(t_thread_data *dt, uint8_t type);

//t_thread_data *allocate_thread_data(t_scan *scan, uint16_t amount, uint16_t offset);




void			print_help(t_nmap *nmap);

void			parsing(t_nmap *nmap, int argc, char **argv);

void			parsing_ports(t_nmap *nmap, char *ports);

void			parsing_file(t_nmap *nmap, char *file);

void			exit_nmap(t_nmap *nmap, int exit_opt);

void			free_double_char(char **str);
int				ft_atoi_strict(char *str, int *nb, int freeit);

#endif
