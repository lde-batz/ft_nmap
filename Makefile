# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: lde-batz <lde-batz@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2020/08/15 16:25:16 by lde-batz          #+#    #+#              #
#    Updated: 2020/09/08 10:05:26 by lde-batz         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = ft_nmap

CC=clang

SRC += 	main.c
SRC +=	help.c
SRC +=	parsing.c
SRC +=	parsing_ports.c
SRC +=	parsing_file.c
SRC +=	exit.c 
SRC +=	tools.c
SRC += ft_nmap.c
SRC += scan_builder.c
SRC += display.c
SRC += callback.c
SRC += packet_builder.c
SRC += checksum.c
SRC += threads.c
SRC += send.c
SRC += send_tcp.c
SRC += send_udp.c
SRC += ft_pcap.c
SRC += socket.c
SRC += decoder.c
SRC += handler.c
SRC += signal.c
SRC += report_print.c
SRC += report_conclusion.c


SRC_DIR = srcs/

OBJ_DIR = objects/

OBJ := $(addprefix $(OBJ_DIR), $(SRC:.c=.o))

SRC := $(addprefix $(SRC_DIR), $(SRC))

INC = includes

INCLUDES = $(INC)/ft_nmap.h

LIB = libft

INC_FLAG = -I$(INC) -I$(LIB)

LIB_FLAG = -L ./$(LIB) -lft

LIBPCAP = -lpcap

LIBPTHREAD = -lpthread

#Compile debug flags
CFLAGS += -Wall -Wextra
ifeq ($(d), 1)
	CFLAGS += -g3 -fsanitize=address,undefined
else ifeq ($(d), 2)
	CFLAGS += -g3 -fsanitize=address,undefined
	CFLAGS += -Wpadded -Wpedantic
endif
ifneq ($(err), no)
	CFLAGS += -Werror
endif

GCC = $(CC) $(CFLAGS)

.SILENT:

all: lib $(NAME)

$(NAME): $(OBJ)
	$(GCC) $(INC_FLAG) -o $(NAME) $(SRC) $(LIB_FLAG) $(LIBPCAP) $(LIBPTHREAD)
	printf '\033[32m[ ✔ ] %s\n\033[0m' "Create ft_nmap"

$(OBJ_DIR)%.o: $(SRC_DIR)%.c $(INCLUDES) $(LIB)/libft.a
	mkdir -p $(OBJ_DIR)
	$(GCC) $(INC_FLAG)  -c $< -o $@
	printf '\033[0m[ ✔ ] %s\n\033[0m' "$<"

lib:
	make -C libft

clean:
	make -C libft clean
	rm -f $(OBJ)
	rm -Rf $(OBJ_DIR)
	printf '\033[31m[ ✔ ] %s\n\033[0m' "Clean ft_nmap"

fclean: clean
	make -C libft fclean
	rm -f $(NAME)
	printf '\033[31m[ ✔ ] %s\n\033[0m' "Fclean ft_nmap"

re: fclean all

.PHONY: all clean fclean re

