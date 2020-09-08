/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   signal.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/07 15:06:44 by lde-batz          #+#    #+#             */
/*   Updated: 2020/09/07 15:22:17 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	sig_alarm(int sig, siginfo_t *siginfo, void *context)
{
	if (siginfo && context){}
	if (sig != SIGALRM)
		return ;
	if (g_scan->scanning == 1)
	{
		ft_putchar('.');
		alarm(1);
	}
}
