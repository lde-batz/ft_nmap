/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   checksum.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: seb <seb@student.42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/09/01 12:00:17 by seb               #+#    #+#             */
/*   Updated: 2020/09/02 09:49:23 by seb              ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
/*
uint16_t ft_checksum()
{
    return (0);
}

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