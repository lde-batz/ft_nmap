/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   callback.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/04 18:29:50 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

  
/* Utilitaire de debug 

static char *hex_to_type(uint8_t hex)
{
	if (hex & SCAN_SYN)
		return ("SYN");
	if (hex & SCAN_NULL)
		return ("NULL");
	if (hex & SCAN_ACK)
		return ("ACK");
	if (hex & SCAN_FIN)
		return ("FIN");
	if (hex & SCAN_XMAS)
		return ("XMAS");
	if (hex & SCAN_UDP)
		return ("UDP");
	return ("Unknown.");
}*/

void	no_response(t_thread_data	*thread_data)
{
	uint8_t		(*handlers[5])(t_thread_data *, uint8_t, int8_t) = { &syn_handler,
					&ack_handler, &null_handler, &fin_handler, &xmas_handler};

	for (uint8_t shift = 1, index = 0; shift < 64 && index < 5; shift = shift << 1, index++)
		if (thread_data->current_type == shift)
			handlers[index](thread_data, 0, -1);
}

/* Libpcap dispatch callback */
void	decode_response(uint8_t *data, const struct pcap_pkthdr *hdr, const uint8_t *packet)
{
	t_thread_data	*thread_data;
	u_int32_t		ip_type;
	uint8_t			return_flags;

	thread_data = (t_thread_data *)data;
	(void)hdr;
	pthread_mutex_lock(&(g_scan->mutex));
//	printf("=== Got a %d byte packet ===\n", hdr->len);
	ip_type = decode_ip_packet(packet + ETHER_HDR_LEN);
	
	switch (ip_type)
	{
		case TCP_CODE :
			decode_tcp_packet(thread_data, packet + ETHER_HDR_LEN + sizeof (struct ip));
			break ;

		case UDP_CODE :
			decode_udp_packet(packet + ETHER_HDR_LEN + sizeof (struct ip));
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

int    portscan(t_thread_data *data, uint8_t type, uint16_t port)
{
	//Libpcap
	char        *device;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_t  	*handle;
	char    	errbuf[PCAP_ERRBUF_SIZE];

	/* Récupération du device, et des paremètres résaux */
	device = get_pcap_device(&net, &mask, errbuf);

	/* Ouverture du device et optention du handle */
	handle = open_pcap_device(device, errbuf);
	
	apply_pcap_filter(handle, net, port);
	

	/* CREER SOCKET & ETC... */
	
	/* INSERER CREATION DE PACKET SELON LE TYPE DE SCAN */

	/* INSERER ENVOI DE PACKET ICI */
	send_packet(data, type, port);




	data->current_type = type;
	data->current_port = port;


	pthread_mutex_lock(&(g_scan->mutex));
	/* option 1: set non-blocking (fast) */
	pcap_setnonblock(handle, 1, errbuf);

	pthread_mutex_unlock(&(g_scan->mutex));

	struct timeval t1, t2;
    double elapsedTime = 0.0;
	int dispatcher = 0;
	
    gettimeofday(&t1, NULL);
	while (elapsedTime < TIMEOUT && dispatcher == 0)
	{
		dispatcher = pcap_dispatch(handle, 1, decode_response, (uint8_t*)data);
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
			if (tdata->type & btshift)
			{
				/* Gros debug pour afficher le thread, type de scan et les port associé */
				/*
				pthread_mutex_lock(&(g_scan->mutex));

				dprintf(2, "Thread %lu: Doing %s scan on '%s': Ports: - ",
					tdata->identifier, hex_to_type(btshift), tdata->ipv4);
					
				for (int i = 0; tdata->port_list[i] != 0; i++)
					dprintf(2, "%d ", tdata->port_list[i]);
				dprintf(2, "-\n");

				pthread_mutex_unlock(&(g_scan->mutex));
				*/
				/* Fin du gros debug */
			
				portscan(tdata, btshift, tdata->port_list[i]);
			}
		}
		
		push_report(tdata);
	}
	
	dprintf(2, "\n");
	
	pthread_mutex_lock(&(g_scan->mutex));

	g_scan->threads_running--;
	
	pthread_mutex_unlock(&(g_scan->mutex));
	return (NULL);
}
