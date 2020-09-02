/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   display.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:45:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/01 20:15:16 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void    print_config(t_nmap *nmap)
{
    dprintf(STDERR_FILENO, "Scan configuration:\n");
//  dprintf(STDERR_FILENO, "Target IP: %s (%s)\n", nmap->ip[index], nmap->hostname[index]);
//    dprintf(STDERR_FILENO, "Amount of ports to scan: %d\n", get_intlist_len(nmap->ports));
    dprintf(STDERR_FILENO, "Scan to perform: %s%s%s%s%s%s\n",
        (nmap->type & SCAN_SYN) ?  "SYN " : "",
        (nmap->type & SCAN_NULL) ?  "NULL " : "",
        (nmap->type & SCAN_ACK) ?  "ACK " : "",
        (nmap->type & SCAN_FIN) ?  "FIN " : "",
        (nmap->type & SCAN_XMAS) ?  "XMAS " : "",
        (nmap->type & SCAN_UDP) ?  "UDP " : "");
    dprintf(STDERR_FILENO, "Amount of threads: %d\n", nmap->threads);
    dprintf(STDERR_FILENO, "Go for scan.\n\n");
}