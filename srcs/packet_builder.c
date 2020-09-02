/*
 ** Compute the internet checksum
 */
/*
static unsigned short		csum(unsigned short *ptr, int nbytes)
{
	register long	sum;
	unsigned short	oddbyte;
	register short	answer;

	sum = 0;
	while(nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if(nbytes == 1)
	{
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;
	return(answer);
}*/

/*
 ** Build the UDP part of the packet
 */
/*
static void   create_udp_packet(char *buff, int sport, int dport)
{
	struct iphdr	*iph;
	struct udphdr	*udph;

	iph = (struct iphdr *)(buff);
	udph = (struct udphdr *)(buff + (iph->ihl * 4));

	udph->source = htons((unsigned short)sport);
	udph->dest = htons(dport);
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0;
	udph->check = csum((unsigned short *)&udph, iph->ihl * 4);
}*/

/*
 ** Build the TCP part of the packet
 */
/*
static void   create_tcp_packet(char *buff, int type, int port, struct sockaddr_in *src, struct sockaddr_in *dst)
{
	struct tcphdr		*tcph;
	struct pshdr		psh;

	// TCP header
	tcph = (struct tcphdr *)(buff + sizeof(struct ip));
	// TODO NOT SURE for tcph->source /!\ //
	tcph->source = src->sin_port;
	tcph->dest = htons(port);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->fin = type == SCAN_FIN ? 1 : 0 || type == SCAN_XMAS ? 1 : 0;
	tcph->syn = type == SCAN_SYN ? 1 : 0;
	tcph->rst = 0;
	tcph->psh = type == SCAN_XMAS ? 1 : 0;
	tcph->ack = type == SCAN_ACK ? 1 : 0;
	tcph->urg = type == SCAN_XMAS ? 1 : 0;
	tcph->window = htons(14600);
	tcph->urg_ptr = 0;
	tcph->check = 0;

	// Pseudo-header
	psh.src_addr = src->sin_addr.s_addr;
	psh.dst_addr = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.proto = IPPROTO_TCP;
	psh.tcplen = htons(sizeof(struct tcphdr));
	ft_memcpy(&psh.tcph, tcph, sizeof(struct tcphdr));

	// TCP header checksum
	tcph->check = csum((unsigned short*)&psh , sizeof(struct pshdr));
}*/

/*
 ** Build the IP part of the packet
 */
/*
static void   create_ip_packet(char *buff, int type, struct sockaddr_in *src, struct sockaddr_in *dst)
{
	struct iphdr  *iph;

	iph = (struct iphdr *)buff;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip);
	if (type == SCAN_UDP)
		iph->tot_len += sizeof(struct udphdr);
	else
		iph->tot_len += sizeof(struct tcphdr);
	iph->id = htons (54321);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	if (type == SCAN_UDP)
		iph->protocol = IPPROTO_UDP;
	else
		iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;
	iph->check = csum((unsigned short *)buff, iph->tot_len >> 1);
}*/

/*
 ** Build the complete packet (IP + TCP/UDP)
 */
/*
void	*create_packet(t_host *src, t_host *dst, int port, int type)
{
	char	*buff;

	if (!(buff = (char *)malloc(4096)))
		return (NULL);

	create_ip_packet(buff, type, src->addr, dst->addr);

	if (type == SCAN_UDP)
		create_udp_packet(buff, src->addr->sin_port, port);
	else
		create_tcp_packet(buff, type, port, src->addr, dst->addr);

	return (buff);
}*/