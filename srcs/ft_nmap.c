/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 10:32:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/02 10:22:33 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

t_scan	*g_scan;

void    push_scan(t_nmap *nmap, t_scan *scan)
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

void    build_scan(t_nmap *nmap)
{
    t_scan  *scan;

    dprintf(STDERR_FILENO, " \n");
    for (int i = 0; nmap->ip[i] != NULL; i++)
    {
        dprintf(STDERR_FILENO, "=====> Creating scan for: %s\n", nmap->ip[i]);
        scan = ft_memalloc(sizeof(t_scan));

        scan->name = nmap->hostname[i];
        scan->ip = nmap->ip[i];
        scan->type = nmap->type;
        scan->ports = nmap->ports;
       // scan->sin = NULL;
        scan->report = NULL;
        scan->next = NULL;
        push_scan(nmap, scan);
    }
    for (t_scan *ptr = nmap->scan; ptr != NULL; ptr = ptr->next)
            dprintf(STDERR_FILENO, "  ✔  New scan : target %s (%s).\n\n", ptr->ip, ptr->name);
}



void    ft_nmap(t_nmap *nmap)
{
    uint16_t    ports_per_thread;
    uint16_t    rest_ports;

    //print scan configuration
    print_config(nmap);
    
    // build data structures
    build_scan(nmap);

    for (t_scan *scan_ptr = nmap->scan; scan_ptr != NULL; scan_ptr = scan_ptr->next)
    {
        g_scan = scan_ptr;
        if (nmap->threads == 0)
        {
            t_thread_data *pseudo_thread_data = allocate_thread_data(scan_ptr, 0, 0);
            scan_callback((void*)pseudo_thread_data);
        }
        else
        {
            dispatch_threads(nmap, scan_ptr);
        }
        dprintf(STDERR_FILENO, "Scan for %s finished\n", scan_ptr->ip);
    }
}