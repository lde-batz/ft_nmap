/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   service_name.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/12 12:05:54 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/12 12:43:00 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void init_service_name(t_nmap *nmap)
{
	if (!(nmap->service_name = (char**)malloc(sizeof(char*) * 996)))
	{
		perror("malloc()");
		exit_nmap(nmap, EXIT_FAILURE);
	}
	for (int i = 0; i < 956; i++)
		nmap->service_name[i] = "Unassigned";
	nmap->service_name[1] = "tcpmux";
	nmap->service_name[5] = "rje";
	nmap->service_name[7] = "echo";
	nmap->service_name[9] = "discard";
	nmap->service_name[11] = "systat";
	nmap->service_name[13] = "daytime";
	nmap->service_name[17] = "qotd";
	nmap->service_name[18] = "msp";
	nmap->service_name[19] = "chargen";
	nmap->service_name[20] = "ftp-data";
	nmap->service_name[21] = "ftp";
	nmap->service_name[22] = "ssh";
	nmap->service_name[23] = "telnet";
	nmap->service_name[25] = "smtp";
	nmap->service_name[37] = "time";
	nmap->service_name[39] = "rlp";
	nmap->service_name[42] = "nameserver";
	nmap->service_name[49] = "tacacs";
	nmap->service_name[53] = "domain";
	nmap->service_name[70] = "gopher";
	nmap->service_name[71] = "genius";
	nmap->service_name[79] = "finger";
	nmap->service_name[80] = "http";
	nmap->service_name[88] = "kerberos";
	nmap->service_name[101] = "hostname";
	nmap->service_name[113] = "auth";
	nmap->service_name[115] = "sftp";
	nmap->service_name[143] = "imap";
	nmap->service_name[161] = "snmp";
	nmap->service_name[162] = "snmptrap";
	nmap->service_name[177] = "xdmcp";
	nmap->service_name[194] = "irc";
	nmap->service_name[209] = "qmtp";
	nmap->service_name[213] = "ipx";
	nmap->service_name[389] = "ldap";
	nmap->service_name[427] = "svrloc";
	nmap->service_name[443] = "https";
	nmap->service_name[444] = "snpp";
	nmap->service_name[464] = "kpasswd";
	nmap->service_name[515] = "printer";
	nmap->service_name[532] = "netnews";
	nmap->service_name[544] = "kshell";
	nmap->service_name[546] = "dhcpv6-client";
	nmap->service_name[547] = "dhcpv6-server";
	nmap->service_name[554] = "rtsp";
	nmap->service_name[631] = "ipp";
	nmap->service_name[636] = "ldaps";
	nmap->service_name[694] = "ha-cluster";
	nmap->service_name[749] = "kerberos-adm";
	nmap->service_name[873] = "rsync";
	nmap->service_name[992] = "telnets";
	nmap->service_name[993] = "imaps";
	nmap->service_name[995] = "pop3s";
}