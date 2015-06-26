#! /usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Copyright (c) 2014-2016 Marcello Salvati
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import os
import random
import logging
import re
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  #Gets rid of IPV6 Error when importing scapy
from scapy.all import get_if_addr, get_if_hwaddr

#formatter = logging.Formatter("%(asctime)s [Utils] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
#logger = log_engine.g.setup_logger('utils', formatter)

def set_ip_forwarding(value):
    #logger.debug("Setting ip forwarding to {}".format(value))
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
        file.write(str(value))
        file.close()

def get_ip(interface):
    try:
        ip_address = get_if_addr(interface)
        if (ip_address == "0.0.0.0") or (ip_address is None):
            sys.exit("[-] {} does not have an assigned ip address".format(interface))

        return ip_address
    except Exception as e:
        sys.exit("[-] Error retrieving ip address from {}: {}".format(interface, e))

def get_mac(interface):
    try:
        mac_address = get_if_hwaddr(interface)
        return mac_address
    except Exception as e:
        sys.exit("[-] Error retrieving mac address from {}: {}".format(interface, e))

class logger_setup:

    log_level = None
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

    def setup_logger(self, name, formatter, logfile='./logs/mitmf.log'):
        fileHandler = logging.FileHandler(logfile)
        fileHandler.setFormatter(formatter)
        streamHandler = logging.StreamHandler(sys.stdout)
        streamHandler.setFormatter(formatter)

        logger = logging.getLogger(name)
        logger.propagate = False
        logger.addHandler(streamHandler)
        logger.addHandler(fileHandler)
        logger.setLevel(self.log_level)

        return logger

class iptables:

    __shared_state = {}

    def __init__(self):
        self.__dict__  = self.__shared_state
        self._dns       = False
        self._http      = False
        self._smb       = False

    def flush(self):
        #logger.debug("Flushing iptables")
        os.system('iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
        self._dns  = False
        self._http = False

    def http(self, http_redir_port):
        #logger.debug("Setting iptables HTTP redirection rule from port 80 to {}".format(http_redir_port))
        os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {}'.format(http_redir_port))
        self._http = True

    def dns(self, dns_redir_port):
        #logger.debug("Setting iptables DNS redirection rule from port 53 to {}".format(dns_redir_port))
        os.system('iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port {}'.format(dns_redir_port))
        self._dns = True

    def smb(self, smb_redir_port):
        #logger.debug("Setting iptables SMB redirection rule from port 445 to {}".format(smb_redir_port))
        os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 445 -j REDIRECT --to-port {}'.format(smb_redir_port))
        self._smb = True

class banners:

    banner1 = """                                                    
 __  __   ___   .--.          __  __   ___              
|  |/  `.'   `. |__|         |  |/  `.'   `.      _.._  
|   .-.  .-.   '.--.     .|  |   .-.  .-.   '   .' .._| 
|  |  |  |  |  ||  |   .' |_ |  |  |  |  |  |   | '     
|  |  |  |  |  ||  | .'     ||  |  |  |  |  | __| |__   
|  |  |  |  |  ||  |'--.  .-'|  |  |  |  |  ||__   __|  
|  |  |  |  |  ||  |   |  |  |  |  |  |  |  |   | |     
|__|  |__|  |__||__|   |  |  |__|  |__|  |__|   | |     
                       |  '.'                   | |     
                       |   /                    | |     
                       `'-'                     |_|
"""

    banner2= """
 ███▄ ▄███▓ ██▓▄▄▄█████▓ ███▄ ▄███▓  █████▒
▓██▒▀█▀ ██▒▓██▒▓  ██▒ ▓▒▓██▒▀█▀ ██▒▓██   ▒ 
▓██    ▓██░▒██▒▒ ▓██░ ▒░▓██    ▓██░▒████ ░ 
▒██    ▒██ ░██░░ ▓██▓ ░ ▒██    ▒██ ░▓█▒  ░ 
▒██▒   ░██▒░██░  ▒██▒ ░ ▒██▒   ░██▒░▒█░    
░ ▒░   ░  ░░▓    ▒ ░░   ░ ▒░   ░  ░ ▒ ░    
░  ░      ░ ▒ ░    ░    ░  ░      ░ ░      
░      ░    ▒ ░  ░      ░      ░    ░ ░    
       ░    ░                  ░                                                     
"""

    banner3 = """
   ▄▄▄▄███▄▄▄▄    ▄█      ███       ▄▄▄▄███▄▄▄▄      ▄████████ 
 ▄██▀▀▀███▀▀▀██▄ ███  ▀█████████▄ ▄██▀▀▀███▀▀▀██▄   ███    ███ 
 ███   ███   ███ ███▌    ▀███▀▀██ ███   ███   ███   ███    █▀  
 ███   ███   ███ ███▌     ███   ▀ ███   ███   ███  ▄███▄▄▄     
 ███   ███   ███ ███▌     ███     ███   ███   ███ ▀▀███▀▀▀     
 ███   ███   ███ ███      ███     ███   ███   ███   ███        
 ███   ███   ███ ███      ███     ███   ███   ███   ███        
  ▀█   ███   █▀  █▀      ▄████▀    ▀█   ███   █▀    ███        
"""

    banner4 = """
      ___                                     ___           ___     
     /\  \                                   /\  \         /\__\    
    |::\  \       ___           ___         |::\  \       /:/ _/_   
    |:|:\  \     /\__\         /\__\        |:|:\  \     /:/ /\__\  
  __|:|\:\  \   /:/__/        /:/  /      __|:|\:\  \   /:/ /:/  /  
 /::::|_\:\__\ /::\  \       /:/__/      /::::|_\:\__\ /:/_/:/  /   
 \:\~~\  \/__/ \/\:\  \__   /::\  \      \:\~~\  \/__/ \:\/:/  /    
  \:\  \        ~~\:\/\__\ /:/\:\  \      \:\  \        \::/__/     
   \:\  \          \::/  / \/__\:\  \      \:\  \        \:\  \     
    \:\__\         /:/  /       \:\__\      \:\__\        \:\__\    
     \/__/         \/__/         \/__/       \/__/         \/__/    
"""
    
    banner5 = """
███╗   ███╗██╗████████╗███╗   ███╗███████╗
████╗ ████║██║╚══██╔══╝████╗ ████║██╔════╝
██╔████╔██║██║   ██║   ██╔████╔██║█████╗  
██║╚██╔╝██║██║   ██║   ██║╚██╔╝██║██╔══╝  
██║ ╚═╝ ██║██║   ██║   ██║ ╚═╝ ██║██║     
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝     
"""
    
    def get_banner(self):
        banners = [self.banner1, self.banner2, self.banner3, self.banner4, self.banner5]
        return random.choice(banners)
