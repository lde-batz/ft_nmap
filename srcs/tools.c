/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tools.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/08/15 17:26:15 by lde-batz          #+#    #+#             */
/*   Updated: 2020/08/16 15:47:33 by lde-batz         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void	free_double_char(char **str)
{
	int i;

	i = -1;
	while (str[++i])
		free(str[i]);
	free(str);
}

int		ft_atoi_strict(char *str, int *nb, int freeit)
{
	size_t i;
	size_t sign;

	i = 0;
	sign = 1;
	*nb = 0;
	while ((str[i] >= 9 && str[i] <= 13) || str[i] == 32)
		i++;
	if (str[i] == '-' || str[i] == '+')
		sign = (str[i++] == 45) ? -1 : 1;
	while (str[i] >= '0' && str[i] <= '9')
		*nb = *nb * 10 + (str[i++] - '0');
	if (freeit)
		free(str);
	*nb *= sign;
	if (str[i])
		return (0);
	return (1);
}
