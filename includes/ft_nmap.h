/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 16:22:45 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/14 15:01:21 by seb              ###   ########.fr       */
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
# include <sys/time.h>
# include <signal.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/in.h>
# include <ifaddrs.h>

#define ETHER_ADDR_LEN		6
#define ETHER_HDR_LEN		14
#define ICMP_CODE			1
#define TCP_CODE			6
#define UDP_CODE			17

# define SCAN_DEF			0xFF
# define SCAN_SYN			0x01
# define SCAN_NULL			0x04 
# define SCAN_ACK			0x02
# define SCAN_FIN			0x08
# define SCAN_XMAS			0x10
# define SCAN_MAI			0x20
# define SCAN_UDP			0x40
# define SCAN_CON			0x80

# define MAX_PORTS			1024
# define TIMEOUT			500
# define RETRIES			2

# define PORT_CLOSED		0x1
# define PORT_OPEN			0x2
# define PORT_FILTERED		0x4
# define PORT_UNFILTERED 	0x8
# define PORT_UNKNOWN		0

typedef struct				s_num_ports
{
	int						nb1;
	int						nb2;
	struct s_num_ports		*next;
}							t_num_ports;

typedef struct				s_hostname_file
{
	char					*hostname;
	char					*ip;
	struct s_hostname_file	*next;
}							t_hostname_file;

typedef struct				s_pseudo_header
{
	unsigned int			source_address;
	unsigned int			dest_address;
	unsigned char			placeholder;
	unsigned char			protocol;
	unsigned short			tcp_length;
	struct tcphdr			tcp;
}							t_pseudo_header;

typedef struct 				s_scan_report
{
	uint16_t				portnumber;
	uint8_t					syn_status;
	uint8_t					ack_status;
	uint8_t					null_status;
	uint8_t					fin_status;
	uint8_t					xmas_status;
	uint8_t					udp_status;
	uint8_t					con_status;
	uint8_t					mai_status;
	uint8_t					conclusion;
	uint8_t					udp_mismatch;
	struct s_scan_report	 *next;
}							t_scan_report;

typedef struct				s_thread_data
{
	pthread_t				identifier;
	char					*hostname;
	char					*ipv4;
	char					*src_ipv4;
	struct sockaddr_in		*sin;
	uint16_t				current_port;
	uint8_t					current_type;
	uint16_t				*port_list;
	t_scan_report			*report;
	uint8_t					type;
	uint32_t				seq;
	uint32_t				ack;
	uint8_t					mismatch;
	struct s_thread_data	 *next;
}							t_thread_data;

typedef struct 				s_scan
{
	char					*name;	
	char					*ip;
	u_int8_t				scanning;
	struct s_scan			*next;
	uint8_t					type;
	t_scan_report			*report;
	t_scan_report			*report_open;
	t_thread_data			*threads;
	pthread_mutex_t			mutex;
	uint16_t				*ports;
	uint8_t					udp_auth;
}							t_scan;

extern t_scan				*g_scan;

typedef struct				s_nmap
{
	char					**ip;
	char					**hostname;
	int						ip_len;
	int						threads;
	char					type;
	uint16_t				*ports;
	uint16_t				ports_len;
	t_scan					*scan;
	char					**service_name;
}							t_nmap;


uint8_t			syn_handler(t_thread_data *thread_data, uint8_t flags, int8_t icmp_code);
uint8_t			ack_handler(t_thread_data *thread_data, uint8_t flags, int8_t icmp_code);
uint8_t			null_handler(t_thread_data *thread_data, uint8_t flags, int8_t icmp_code);
uint8_t			fin_handler(t_thread_data *thread_data, uint8_t flags, int8_t icmp_code);
uint8_t			xmas_handler(t_thread_data *thread_data, uint8_t flags, int8_t icmp_code);
uint8_t			udp_handler(t_thread_data *thread_data, uint8_t flags, int8_t icmp_code);
uint8_t			mai_handler(t_thread_data *thread_data, uint8_t tcp_flags, int8_t icmp_code);

void			free_scanlist(t_nmap *nmap);
void			free_reports(t_scan *scan);
void			free_thread_data(t_thread_data *dt);
void			free_threads_data(t_scan *sc);

void			ft_nmap(t_nmap *nmap);
void			build_scanlist(t_nmap *nmap);

t_thread_data	*allocate_thread_data(t_scan *scan, uint16_t amount, uint16_t offset);
void			dispatch_threads(t_nmap *nmap, t_scan *scan);
void			*scan_callback(void *data);

char			*get_pcap_device(bpf_u_int32 *net, bpf_u_int32 *mask, char errbuf[1024]);
pcap_t			*open_pcap_device(char *device, char errbuf[1024]);
void			apply_pcap_filter(t_thread_data *dt, pcap_t *handle, bpf_u_int32 net, uint16_t port);

uint16_t		get_portnb(uint16_t *ports);

int				send_packet(t_thread_data *data, uint8_t type, uint16_t port);
void			send_tcp_packet(t_thread_data *data, uint8_t type, uint16_t port);
void			send_udp_packet(t_thread_data *data, uint16_t port);
int				checksum(unsigned short	*buf, int len);

uint32_t		decode_ip_packet(const uint8_t *header_start);
uint8_t			decode_tcp_packet(t_thread_data *thread_data, const uint8_t *header_start);
uint32_t		decode_udp_packet(t_thread_data *thread_data, const uint8_t *header_start);
uint32_t		decode_icmp_packet(t_thread_data *thread_data, const uint8_t *buffer);

void			show_report(t_scan *scan, t_nmap *nmap);
void			set_conclusion_report(t_scan *scan);

void			sig_alarm(int sig, siginfo_t *siginfo, void *context);

int				portscan(t_thread_data *data, uint8_t type, uint16_t port);

void			print_help(t_nmap *nmap);

void			parsing(t_nmap *nmap, int argc, char **argv);

void			parsing_ports(t_nmap *nmap, char *ports);

void			parsing_file(t_nmap *nmap, char *file);

void			init_service_name(t_nmap *nmap);

void			exit_nmap(t_nmap *nmap, int exit_opt);

void			free_double_char(char **str);
int				ft_atoi_strict(char *str, int *nb, int freeit);

#endif
