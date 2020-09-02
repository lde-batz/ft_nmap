#include "ft_nmap.h"

/*
** Send the complete packet
*/
int		send_packet(t_host *src, t_host *dst, int sock, int port, int type)
{
	void	*packet;
	int		packet_size;
	int		ret;

	ret = -1;
	if ((packet = create_packet(src, dst, port, type)))
	{
		if (type == SCAN_UDP)
			packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
		else
			packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
		
		if ((ret = sendto(sock, packet, packet_size, 0, (struct sockaddr *)dst->addr, sizeof(struct sockaddr))) < 0)
		{
			if (info.verbose)
				printf("Error: Unable to send probe from %s to %s on port %d\n", src->name, dst->name, port);
		}
		else
		{
			if (info.verbose)
				printf("Probe sent from %s to %s on port %d\n", src->name, dst->name, port);
		}
		
		free(packet);
	}
	else
	{
		if (info.verbose)
			printf("Error: Unable to build probe from %s to %s on port %d\n", src->name, dst->name, port);
	}
	return (ret);
}
