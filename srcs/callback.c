/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   callback.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/02 15:38:17 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

/*   Juste du debug inutile
void print_packet_info(const uint8_t *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

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
	struct ip	*ip;

	ip = (struct ip*)packet;
	
}

int    portscan(t_thread_data *data, uint8_t type)
{
	//Libpcap
	char        *device;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_t  	*handle;
	char    	errbuf[PCAP_ERRBUF_SIZE];

	
	pthread_mutex_lock(&(g_scan->mutex));
	
	/* Détection du device réseau */
	if ((device = pcap_lookupdev(errbuf)) == NULL)
	{
		dprintf(STDERR_FILENO, "Error: pcap_lookupdev() failed: %s\n", errbuf);
		pthread_exit(NULL);
	}

	/* Détéction et stockage du réseau & netmask */
	if (pcap_lookupnet(device, &net, &mask, errbuf) != 0)
	{
		dprintf(STDERR_FILENO, "Error: pcap_lookupnet() failed: %s\n", errbuf);
		pthread_exit(NULL);
	}

	/* Ouverture du device pour live capture */
	ft_memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	if ((handle = pcap_open_live(device, BUFSIZ, 1, 3, errbuf)) == NULL)
	{
		dprintf(STDERR_FILENO, "Error: pcap_open_live() failed: %s\n", errbuf);
		pthread_exit(NULL);
	}
	if (ft_strlen(errbuf) != 0)
		dprintf(STDERR_FILENO, "Warning: pcap_open_live(): %s\n", errbuf);

	pthread_mutex_unlock(&(g_scan->mutex));

	pthread_mutex_lock(&(g_scan->mutex));

	/* Création du filtre */
	char		filter[1024];
	struct		bpf_program	bpf;

	sprintf(filter, "src port %d", 80);
//	sprintf(filter, "src host %s and src port %d and dst host %s", );

	/* Compilation du filtre */
	if (pcap_compile(handle, &bpf, filter, 0, net) == -1)
	{
		dprintf(STDERR_FILENO, "Error: Unable to compile pcap filter: '%s'\n", filter);
		pcap_close(handle);
		pthread_exit(NULL);
	}

	/* Application du filtre */
	if (pcap_setfilter(handle, &bpf) == -1)
	{
		dprintf(STDERR_FILENO, "Error: Unable to apply pcap filter\n");
		pcap_close(handle);
		pthread_exit(NULL);
	}
	
	/* Libération mémoire du filtre (une fois appliqué) */
	pcap_freecode(&bpf);

	pthread_mutex_unlock(&(g_scan->mutex));


	/* INSERER CREATION DE PACKET SELON LE TYPE DE SCAN */

	/* INSERER ENVOI DE PACKET ICI */

	/* INSERER RéCUPéRATION DE PACKET AVE LIBPCAP */
	//pcap_dispatch(handle, 1, decode_response, argument);

	pcap_close(handle);

	return (0);
}

void    *scan_callback(void *callback_data)
{
	t_thread_data *data;
	
	/* Vérification de la data (inutile?) */
	if (callback_data == NULL)
	{
		pthread_mutex_lock(&(g_scan->mutex));

		g_scan->threads_running--;
		dprintf(STDERR_FILENO, "Error: Thread callback is data undefined.\n");
		
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}

	data = (struct s_thread_data*)callback_data;
	for (uint8_t btshift = 1; btshift < 64; btshift = btshift << 1)
	{
		if (data->type & btshift)
		{
			/* Gros debug pour afficher le thread, type de scan et les port associé */
			pthread_mutex_lock(&(g_scan->mutex));
			
			dprintf(2, "Thread %lu: Doing %s scan on '%s': Ports: - ",
					data->identifier, hex_to_type(btshift), data->ipv4);
					
			for (int i = 0; data->port_list[i] != 0; i++)
				dprintf(2, "%d ", data->port_list[i]);
			dprintf(2, "-\n");

			pthread_mutex_unlock(&(g_scan->mutex));
			/* Fin du gros debug */
			
			//portscan(data, btshift);
		}
	}
	dprintf(2, "\n");
	
	pthread_mutex_lock(&(g_scan->mutex));

	g_scan->threads_running--;
	
	pthread_mutex_unlock(&(g_scan->mutex));
	return (NULL);
}