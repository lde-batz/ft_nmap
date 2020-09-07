/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   threads.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/02 08:33:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/07 10:56:27 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/* Push les structures thread_data dans la liste 'scan->threads' */
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

/* Récupere les 'am' premiers elements de la liste 'source', a partir de 'offset' */
static uint16_t		*list_range(uint16_t *source, uint16_t am, uint16_t offset)
{
	uint16_t	*list;

	if (am == 0)
		am = get_portnb(source);
	
	list = (uint16_t*)ft_memalloc(sizeof(uint16_t) * (am + 1));
	ft_memset(list, 0, sizeof(uint16_t) * (am + 1));
	
	for (int i = 0; i < am; i++)
		list[i] = source[i + offset];
		
	return (list);
}

t_thread_data *allocate_thread_data(t_scan *scan, uint16_t amount, uint16_t offset)
{
	t_thread_data *dt;

	if (!(dt = ft_memalloc(sizeof(t_thread_data))))
    {
        dprintf(STDERR_FILENO, "Error: Could not allocate memory for thread_data structure.\n");
        exit(EXIT_FAILURE);
    }
	dt->identifier = 0;
	dt->hostname = scan->name;
	dt->ipv4 = scan->ip;
    dt->type = scan->type;
	dt->sin = NULL;
    dt->next = NULL;
    
    /* Copie les ports afftecté au thread dans sa liste personnel */
	dt->port_list = list_range(scan->ports, amount, offset);
	return (dt);
}

/* Lance le thread, avec le callback, et la strucutre thread_data en argument du callback. */
/* Si le thread est lancé, la structure thread_data est push sur la liste de thread en exec. */
/* Et la variable 'scan->threads_running' est incrémenté. */
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

    /* Calcul de la distribution des ports */
	ports_per_thread = get_portnb(nmap->ports) / nmap->threads;

    /* Si nous avons plus de thread que de ports, fixer le nb. de thread au nb. de ports */
	if (ports_per_thread == 0)
	{
		for (int i = 0; i < get_portnb(nmap->ports); i++)
		{
			thread_data = allocate_thread_data(scan, 1, i);

			launch_thread(scan, thread_data);
		}
	}
	else /* Dispatcher les ports sur tout les threads */
	{
        int offset = 0;
		rest_ports = get_portnb(nmap->ports) % nmap->threads;
		for (int i = 0; i < nmap->threads;i++)
		{
			if (rest_ports == 0) /* Pas de ports supplémentaire a dispatcher */
			{
				thread_data = allocate_thread_data(scan, ports_per_thread, offset);
				offset += ports_per_thread;
			}
			else /* Dispatcher les ports supplémentaires */
			{
				thread_data = allocate_thread_data(scan, ports_per_thread + 1, offset);
                offset += ports_per_thread + 1;
				--rest_ports;
			}
//			dprintf(2, "Thread %s ports: ", thread_data->ipv4);
//			for (int i = 0; thread_data->port_list[i] != 0; i++)
//					dprintf(2, "%d ", thread_data->port_list[i]);
//			dprintf(2, "\n");
			launch_thread(scan, thread_data);
		}
	}
	/* Itération sur tout les thread, et attendre leur fin d'execution avec pthread_join() */
	for (t_thread_data *td = scan->threads; td != NULL; td = td->next)
	{
		if(pthread_join(td->identifier, NULL) != 0)
			dprintf(STDERR_FILENO, "Thread |%lu| join failed\n", td->identifier);
	}
}