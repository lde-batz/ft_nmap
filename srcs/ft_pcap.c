/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_pcap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/02 17:47:05 by seb               #+#    #+#             */
/*   Updated: 2020/09/02 17:51:32 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

char	*get_pcap_device(bpf_u_int32 *net, bpf_u_int32 *mask, char errbuf[1024])
{
	char *device;

	pthread_mutex_lock(&(g_scan->mutex));
	
	/* Détection du device réseau */
	if ((device = pcap_lookupdev(errbuf)) == NULL)
	{
		dprintf(STDERR_FILENO, "Error: pcap_lookupdev() failed: %s\n", errbuf);
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}

	/* Détéction et stockage du réseau & netmask */
	if (pcap_lookupnet(device, net, mask, errbuf) != 0)
	{
		dprintf(STDERR_FILENO, "Error: pcap_lookupnet() failed: %s\n", errbuf);
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}
	
	pthread_mutex_unlock(&(g_scan->mutex));
	return (device);
}

pcap_t	*open_pcap_device(char *device, char errbuf[1024])
{
	pcap_t	*handle;

	pthread_mutex_lock(&(g_scan->mutex));
	
	/* Ouverture du device pour live capture */
	ft_memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	if ((handle = pcap_open_live(device, BUFSIZ, 1, 3, errbuf)) == NULL)
	{
		dprintf(STDERR_FILENO, "Error: pcap_open_live() failed: %s\n", errbuf);
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}
	if (ft_strlen(errbuf) != 0)
		dprintf(STDERR_FILENO, "Warning: pcap_open_live(): %s\n", errbuf);
		
	pthread_mutex_unlock(&(g_scan->mutex));
	return (handle);
}

void	apply_pcap_filter(pcap_t *handle, bpf_u_int32 net)
{
	char		filter[512];
	struct		bpf_program	bpf;

	pthread_mutex_lock(&(g_scan->mutex));
	
	sprintf(filter, "src port %d or dst port 80", 80);
	//	sprintf(filter, "src host %s and src port %d and dst host %s", );

	/* Compilation du filtre */
	if (pcap_compile(handle, &bpf, filter, 0, net) == -1)
	{
		dprintf(STDERR_FILENO, "Error: Unable to compile pcap filter: '%s'\n", filter);
		pcap_close(handle);
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}

	/* Application du filtre */
	if (pcap_setfilter(handle, &bpf) == -1)
	{
		dprintf(STDERR_FILENO, "Error: Unable to apply pcap filter\n");
		pcap_freecode(&bpf);
		pcap_close(handle);
		pthread_mutex_unlock(&(g_scan->mutex));
		pthread_exit(NULL);
	}
	pcap_freecode(&bpf);
	
	pthread_mutex_unlock(&(g_scan->mutex));
}