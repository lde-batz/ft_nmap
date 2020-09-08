/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   callback.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/07 18:26:44 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

void	no_response(t_thread_data	*thread_data)
{
	uint8_t		(*handlers[6])(t_thread_data *, uint8_t, int8_t) = { &syn_handler,
					&ack_handler, &null_handler, &fin_handler, &xmas_handler, &udp_handler};

	for (uint8_t shift = 1, index = 0; shift < 64 && index < 6; shift = shift << 1, index++)
		if (thread_data->current_type == shift)
			handlers[index](thread_data, 0, -1);
}

/* Libpcap dispatch callback */
void	decode_response(uint8_t *data, const struct pcap_pkthdr *hdr, const uint8_t *packet)
{
	t_thread_data	*thread_data;
	u_int32_t		ip_type;

	thread_data = (t_thread_data *)data;
	(void)hdr;
	pthread_mutex_lock(&(g_scan->mutex));
	ip_type = decode_ip_packet(packet + ETHER_HDR_LEN);
	switch (ip_type)
	{
		case TCP_CODE :
			decode_tcp_packet(thread_data, packet + ETHER_HDR_LEN + sizeof (struct ip));
			break ;

		case UDP_CODE :
			decode_udp_packet(thread_data, packet + ETHER_HDR_LEN + sizeof (struct ip));
			break ;

		case ICMP_CODE:
			decode_icmp_packet(thread_data, packet + ETHER_HDR_LEN + sizeof (struct ip));
			break ;
			
		default :
			printf(" --- Layer 4 protocol not supported: %u ---\n", ip_type);
			break ;
	}
	pthread_mutex_unlock(&(g_scan->mutex));
}

/* Add error handling */
void	get_device_ip(t_thread_data *data, char *device)
{
	struct ifaddrs	    *ifap;
	struct ifaddrs		*p;
	struct sockaddr_in	*sa;
		
	if (getifaddrs(&ifap) == -1)
		return ;
	p = ifap;
	while (p)
	{
		if (p->ifa_addr->sa_family == AF_INET && strcmp(p->ifa_name, device) == 0)
		{
			sa = (struct sockaddr_in *)p->ifa_addr;
			data->src_ipv4 = ft_strnew(32, 0);
			ft_strcpy(data->src_ipv4, inet_ntoa(sa->sin_addr));
			break;
		}
		p = p->ifa_next;
	}
}

static uint32_t ft_abs(int32_t abs)
{
	return (abs < 0) ? -abs : abs;
}

int    portscan(t_thread_data *data, uint8_t type, uint16_t port)
{
	char        *device;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_t  	*handle;
	char    	errbuf[PCAP_ERRBUF_SIZE];
	struct 		timeval t1, t2;
    double 		elapsedTime = 0.0;
	int 		dispatcher = 0;

	data->current_type = type;
	data->current_port = port;

	/* Récupération du device, et des paremètres résaux */
	device = get_pcap_device(&net, &mask, errbuf);

	/* Obtention de l'ip du device */
	get_device_ip(data, device);
	
	/* Ouverture du device et optention du handle */
	handle = open_pcap_device(device, errbuf);
	
	/* Application des filtres de capture */
	apply_pcap_filter(data, handle, net, port);

	/* Seq/Ack */
	data->seq = htonl(ft_abs(data->identifier + (port * 2) + type));
	//dprintf(2, "Seq is %u\n", data->seq);
	
	/* Envois de packets */
	send_packet(data, type, port);
	
	/* option 1: set non-blocking (fast) */
	pcap_setnonblock(handle, 1, errbuf);

	
	data->mismatch = 1;
    gettimeofday(&t1, NULL);
	while (elapsedTime < TIMEOUT && dispatcher == 0)
	{
		dispatcher = pcap_dispatch(handle, 1, decode_response, (uint8_t*)data);
		if (data->mismatch == 1)
			dispatcher = 0;
		gettimeofday(&t2, NULL);
		elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;
   		elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;
	}
	if (dispatcher == 0)	/* Timeout */
		no_response(data);
	
	pcap_close(handle);

	return (0);
}

t_scan_report   *create_scan_report(uint16_t port)
{
    t_scan_report *report;

    report = ft_memalloc(sizeof(struct s_scan_report));
    ft_memset(report, 0, sizeof(struct s_scan_report));
	report->portnumber = port;
	report->next = NULL;
    return (report);
}

void	push_report(t_thread_data *dt)
{
	pthread_mutex_lock(&(g_scan->mutex));
	
	if (g_scan->report == NULL)
		g_scan->report = dt->report;
	else
	{
		t_scan_report *sr = g_scan->report;
		while (sr->next != NULL)
			sr = sr->next;
		sr->next = dt->report;
	}

	pthread_mutex_unlock(&(g_scan->mutex));
}

void    *scan_callback(void *callback_data)
{
	t_thread_data 		*tdata;
	
	/* Vérification de la data (inutile?) */
	if (callback_data == NULL)
	{
		pthread_mutex_lock(&(g_scan->mutex));

		g_scan->threads_running--;
		dprintf(STDERR_FILENO, "Error: Thread callback is data undefined.\n");
		
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}

	tdata = (struct s_thread_data*)callback_data;
	
	for (int i = 0; tdata->port_list[i] != 0; i++)
	{ /* for every  port */

		tdata->report = create_scan_report(tdata->port_list[i]);
		
		for (uint8_t btshift = 1; btshift < 64; btshift = btshift << 1)
		{
			if (tdata->type & btshift) {
				portscan(tdata, btshift, tdata->port_list[i]);
			}
		}
		push_report(tdata);
	}
	
	dprintf(2, "\n");

	g_scan->threads_running--;
	
	pthread_mutex_unlock(&(g_scan->mutex));
	return (NULL);
}
