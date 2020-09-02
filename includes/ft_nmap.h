/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 16:22:45 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/02 18:30:38 by seb              ###   ########.fr       */
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
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;			/* version << 4 | header length >> 2 */
	u_char ip_tos;			/* type of service */
	u_short ip_len;			/* total length */
	u_short ip_id;			/* identification */
	u_short ip_off;			/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;			/* time to live */
	u_char ip_p;			/* protocol */
	u_short ip_sum;			/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};



# define SCAN_SYN	0x20
# define SCAN_NULL	0x10 
# define SCAN_ACK	0x08
# define SCAN_FIN	0x04
# define SCAN_XMAS	0x02
# define SCAN_UDP	0x01 

# define MAX_PORTS 1024
# define TIMEOUT_MS	2

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
void			apply_pcap_filter(pcap_t *handle, bpf_u_int32 net, uint16_t port);

uint16_t	get_portnb(uint16_t *ports);
uint16_t	ft_checksum();

//void		craft_packet();

int    portscan(t_thread_data *data, uint8_t type, uint16_t port);

//t_thread_data *allocate_thread_data(t_scan *scan, uint16_t amount, uint16_t offset);




void			print_help(t_nmap *nmap);

void			parsing(t_nmap *nmap, int argc, char **argv);

void			parsing_ports(t_nmap *nmap, char *ports);

void			parsing_file(t_nmap *nmap, char *file);

void			exit_nmap(t_nmap *nmap, int exit_opt);

void			free_double_char(char **str);
int				ft_atoi_strict(char *str, int *nb, int freeit);

#endif
