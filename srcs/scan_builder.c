/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_builder.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/02 12:51:01 by seb               #+#    #+#             */
/*   Updated: 2020/09/04 12:05:48 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void    push_scan(t_nmap *nmap, t_scan *scan)
{
    t_scan *scan_ptr;

    scan_ptr = NULL;
    if (nmap->scan == NULL)
        nmap->scan = scan;
    else
    {
        scan_ptr = nmap->scan;
        while (scan_ptr->next != NULL)
            scan_ptr = scan_ptr->next;
        scan_ptr->next = scan;
    }
}

void    build_scanlist(t_nmap *nmap)
{
    t_scan  *scan;

    for (int i = 0; nmap->ip[i] != NULL; i++)
    {
        dprintf(STDERR_FILENO, "=====> Creating scan for: %s\n", nmap->ip[i]);
        if (!(scan = ft_memalloc(sizeof(t_scan))))
        {
            dprintf(STDERR_FILENO, "Error: Could not allocate memory for scan structure.\n");
            exit(EXIT_FAILURE);
        }
        scan->name = nmap->hostname[i];
        scan->ip = nmap->ip[i];
        scan->type = nmap->type;
        scan->ports = nmap->ports;
        scan->report = NULL;
        scan->next = NULL;
        push_scan(nmap, scan);
    }
    
    /* Debug scan structure listing */
    for (t_scan *ptr = nmap->scan; ptr != NULL; ptr = ptr->next)
        dprintf(STDERR_FILENO, "  ✔  New scan : target %s (%s).\n", ptr->ip, ptr->name);
    dprintf(STDERR_FILENO, "\n");
}