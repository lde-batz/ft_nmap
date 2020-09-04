/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   callback.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/03 17:46:55 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

  
/*
uint32_t	decode_ip_packet(const uint8_t *header_start)
{
	const struct ip_hdr		*ip_header;

	ip_header = (const struct ip_hdr*) header_start;
	printf("\t((  Layer 3 ::: IP Header  ))\n");

	printf("\t( Source: %s\t", inet_ntoa(*(struct in_addr*)&(ip_header->ip_src_addr)));
	printf("Dest: %s )\n", inet_ntoa(*(struct in_addr*)&(ip_header->ip_dst_addr)));
	printf("\t( Type: %u\t", (uint32_t) ip_header->ip_type);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ip_header->ip_len);
	return ((uint32_t) ip_header->ip_type);
}
*/

/* utilitaire de debug */
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
}

/* Libpcap dispatch callback */
void	decode_response(uint8_t *args, const struct pcap_pkthdr *hdr, const uint8_t *packet)
{
	(void)args;
	(void)hdr;
	
	const struct ip *iphdr; /* The IP header */

	iphdr = (struct ip*)(packet + SIZE_ETHERNET);
	
	pthread_mutex_lock(&(g_scan->mutex));

	dprintf(STDERR_FILENO, "Caught a %hu bytes packet\n", ntohs(iphdr->ip_len));

	pthread_mutex_unlock(&(g_scan->mutex));

}

void print_packet_info(uint8_t *args, const struct pcap_pkthdr packet_header, const uint8_t *packet)
{
	(void)args;(void)packet;
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

int    portscan(t_thread_data *data, uint8_t type, uint16_t port)
{
	(void)data;(void)type;
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

	/* INSERER RéCUPéRATION DE PACKET AVE LIBPCAP */

	pcap_dispatch(handle, 1, decode_response, NULL);

	pcap_close(handle);

	return (0);
}

void    *scan_callback(void *callback_data)
{
	t_thread_data *tdata;
	
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
	/* Itération sur le field 'type' pour effecter chaque scan */
	for (uint8_t btshift = 1; btshift < 64; btshift = btshift << 1)
	{
		if (tdata->type & btshift)
		{
			/* Gros debug pour afficher le thread, type de scan et les port associé */
			pthread_mutex_lock(&(g_scan->mutex));
			
			dprintf(2, "Thread %lu: Doing %s scan on '%s': Ports: - ",
					tdata->identifier, hex_to_type(btshift), tdata->ipv4);
					
			for (int i = 0; tdata->port_list[i] != 0; i++)
				dprintf(2, "%d ", tdata->port_list[i]);
			dprintf(2, "-\n");

			pthread_mutex_unlock(&(g_scan->mutex));
			/* Fin du gros debug */
			for (int i = 0; tdata->port_list[i] != 0; i++)
				portscan(tdata, btshift, tdata->port_list[i]);
		}
	}
	dprintf(2, "\n");
	
	pthread_mutex_lock(&(g_scan->mutex));

	g_scan->threads_running--;
	
	pthread_mutex_unlock(&(g_scan->mutex));
	return (NULL);
}