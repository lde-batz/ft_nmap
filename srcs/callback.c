/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   callback.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:49:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/02 12:23:38 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

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

void	decode_response(uint8_t *args, const struct pcap_pkthdr *hdr, const uint8_t *packet)
{
	struct ip	*ip;

	ip = (struct ip*)packet;
	dprintf(STDOUT_FILENO, "Packet of size %hu bytes:\n", htons(ip->ip_len));

	//dprintf(STDOUT_FILENO, "Source: %s - Dest: %s\n", inet_aton(((struct in_addr*)&(ip->ip_src))));
}

int    portscan(t_thread_data *data, uint8_t type)
{
	// Socket
	int     sock;
	
	//Libpcap
	char        *device;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_t  	*handle;
	char    	errbuf[PCAP_ERRBUF_SIZE];


	pthread_mutex_lock(&(g_scan->mutex));
	if ((device = pcap_lookupdev(errbuf)) == NULL)
	{
		dprintf(STDERR_FILENO, "Error: pcap_lookupdev() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&(g_scan->mutex));

	//Libpcap: lookupnet - get netmask and subnet
	pthread_mutex_lock(&(g_scan->mutex));
	if (pcap_lookupnet(device, &net, &mask, errbuf) != 0)
	{
		dprintf(STDERR_FILENO, "Error: pcap_lookupnet() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&(g_scan->mutex));

	pthread_mutex_lock(&(g_scan->mutex));
	ft_memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	if ((handle = pcap_open_live(device, BUFSIZ, 1, 3, errbuf)) == NULL)
	{
		dprintf(STDERR_FILENO, "Error: pcap_open_live() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	if (ft_strlen(errbuf) != 0)
		dprintf(STDERR_FILENO, "Warning: pcap_open_live(): %s\n", errbuf);
	pthread_mutex_unlock(&(g_scan->mutex));




/*	// Create raw socket first for further sending packets
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		dprintf(STDERR_FILENO, "Failed to create raw socket.\n");
		exit(EXIT_FAILURE);
	}
*/



	char	filter_exp[1024];
	struct	bpf_program	fp;

	sprintf(filter_exp, "dst port %d", 561);
		
		// Compile pcap filter expression
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
		{
			printf("Error: Unable to compile pcap filter\n");
			pcap_close(handle);
			return (-1);
		}

		// Set pcap filter expression
		if (pcap_setfilter(handle, &fp) == -1)
		{
			printf("Error: Unable to set pcap filter\n");
			pcap_close(handle);
			return (-1);
		}
		pcap_freecode(&fp);


	//int ret = pcap_dispatch(handle, 10, decode_response, NULL);

	pcap_close(handle);

	return (0);
}

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

void    *scan_callback(void *callback_data)
{
	// SCAN TYPE --> t_scan
	// Ports to scan (list)
	
	t_thread_data *data;
	
	if (callback_data == NULL)
		dprintf(2, "Error: Callback data null\n");
	data = (struct s_thread_data*)callback_data;

	for (uint8_t btshift = 1; btshift < 64; btshift = btshift << 1)
	{
		if (data->type & btshift)
		{
			pthread_mutex_lock(&(g_scan->mutex));
			dprintf(2, "Thread %lu: Doing %s scan on '%s': Ports: - ", data->identifier,
														hex_to_type(btshift),
														data->ipv4);
			for (int i = 0; data->port_list[i] != 0; i++)
				dprintf(2, "%d ", data->port_list[i]);
			dprintf(2, "-\n");

			pthread_mutex_unlock(&(g_scan->mutex));
			
			//portscan(data, btshift);
		}
	}
	dprintf(2, "\n");
	
/*	// For each port
	while (i < data->len)
	{
		if (info.scans & SCAN_SYN)
		{
			scan(data->host, info.ports[i + data->pidx], SCAN_SYN);
		}
		if (info.scans & SCAN_NULL)
		{
			scan(data->host, info.ports[i + data->pidx], SCAN_NULL);
		}
		i++;
	}
	info.thread_num--;
	free(data);
	return (NULL);*/
	
	return (NULL);
}

static uint16_t		*list_range(uint16_t *source, uint16_t am, uint16_t offset)
{
	uint16_t	*list;

	if (am == 0)
	{
		int j;
		for (j = 0; source[j] != 0; j++) ;
		am = j;
	}
	list = (uint16_t*)ft_memalloc(sizeof(uint16_t) * (am + 1));
	ft_memset(list, 0, sizeof(uint16_t) * (am + 1));
	for (int i = 0; i < am; i++)
		list[i] = source[i + offset];
	return (list);
}

t_thread_data *allocate_thread_data(t_scan *scan, uint16_t amount, uint16_t offset)
{
	t_thread_data *dt;

	dt = ft_memalloc(sizeof(t_thread_data));
	dt->identifier = 0;

	dt->hostname = scan->name; // RO
	dt->ipv4 = scan->ip;       // RO 

	dt->sin = NULL;

	dt->port_list = list_range(scan->ports, amount, offset);
	dt->type = scan->type;
	dt->next = NULL;
	return (dt);
}

void       push_thread_data(t_scan *scan, t_thread_data *dt)
{
	t_thread_data *dt_ptr;

	if (scan->threads == NULL)
		scan->threads = dt;
	else
	{
		dt_ptr = scan->threads;
		while (dt_ptr->next != NULL)
			dt_ptr = dt_ptr->next;
		dt_ptr->next = dt;
	}
}

void    launch_thread(t_scan *scan, t_thread_data *td)
{
	if (pthread_create(&(td->identifier), NULL, scan_callback, (void*)td) == 0)
		{
			push_thread_data(scan, td);
			scan->threads_running++;
		}
		else
			printf("Error: Unable to create thread\n");
}

void    dispatch_threads(t_nmap *nmap, t_scan *scan)
{
	t_thread_data   *thread_data;
	uint16_t        ports_per_thread;
	uint16_t        rest_ports;

dprintf(STDERR_FILENO, "Launching %d threads...\n", nmap->threads);
	ports_per_thread = get_portnb(nmap->ports) / nmap->threads;
    dprintf(STDERR_FILENO, "Scanning ~%d ports per thread\n", ports_per_thread);
	if (ports_per_thread == 0)
	{
		for (int i = 0; i < nmap->threads; i++)
		{
			thread_data = allocate_thread_data(scan, 1, i);
			launch_thread(scan, thread_data);
		}
	}
	else
	{
		rest_ports = get_portnb(nmap->ports) % nmap->threads;
//        dprintf(STDERR_FILENO, "Rest_ports: %d\n", rest_ports);
		int offset = 0;
		for (int i = 0; i < nmap->threads;i++)
		{

			if (rest_ports == 0)
			{
		//        dprintf(STDERR_FILENO, "Dispatching |%d| ports on thread |%d|\n", ports_per_thread, i);
				thread_data = allocate_thread_data(scan, ports_per_thread, offset);
				offset += ports_per_thread;
			}
			else
			{
		  //      dprintf(STDERR_FILENO, "Dispatching |%d| ports on thread |%d|\n", ports_per_thread + 1, i);
				thread_data = allocate_thread_data(scan, ports_per_thread + 1, offset);
				--rest_ports;
				offset += ports_per_thread + 1;
			}

			//dprintf(STDERR_FILENO, "Launching thread %d\n", i);
			launch_thread(scan, thread_data);
		}
		
		for (t_thread_data *td = scan->threads; td != NULL; td = td->next)
		{
			if(pthread_join(td->identifier, NULL) == 0)
			{
		   //     dprintf(2, "Thread |%lu| joined!\n", td->id);
			}   
			else
			{
				dprintf(2, "Thread |%lu| join failed\n", td->identifier);
			}
			
		}
//        dprintf(STDERR_FILENO, "Final rest_ports (MUST BE 0): %d\n", rest_ports);
	}
	
}