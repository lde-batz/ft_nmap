/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_powf.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/06/20 16:14:06 by lde-batz          #+#    #+#             */
/*   Updated: 2020/06/20 16:14:08 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

double	ft_powf(double nb, int power)
{
	double	nbr;
	int		i;

	if (power == 0)
		return (1);
	else if (power > 0)
	{
		nbr = nb;
		i = 1;
		while (i++ < power)
			nbr *= nb;
	}
	else
	{
		nbr = 1;
		i = 0;
		while (i-- > power)
			nbr /= nb;
	}
	return (nbr);
}
