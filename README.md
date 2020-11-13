## Team
#### [lde-batz](https://github.com/lde-batz)

#### [skuppers](https://github.com/skuppers)

# Ft_nmap

Ft_nmap is port scanning project for 42 school.

The goal of this project is to familiarize ourself with the libpcap and the libpthread, aswell as common portscanning techniques and important TCP/IP knowledge.

## Building

Compile with clang:
  
   ``$> make CC=clang``
   
   
## Running ft_nmap

As we use raw sockets, we need to be root. You can see a help menu if you provide no argument.

![image](https://user-images.githubusercontent.com/29956389/93336798-88757200-f828-11ea-9df7-5cfaa01a00b9.png)

A simple command to run a scan is:

`sudo ./ft_nmap --ip <enter-ip> --scan SYN --ports 20,21,22,80,443`.

![image](https://user-images.githubusercontent.com/29956389/93337047-e1450a80-f828-11ea-829a-77de382ac3b7.png)

A different command can be:

`sudo ./ft_nmap --ip <enter-ip> --scan CON/ACK/XMAS --ports 20,21,22,80,443 --speedup 2`.

![image](https://user-images.githubusercontent.com/29956389/93337263-3254fe80-f829-11ea-8e91-b13fc8e34177.png)
