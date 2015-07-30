#! /usr/bin/env python2.7

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

import argparse
import threading
import logging
import sys
import os

from libmproxy import proxy
from libmproxy.proxy.server import ProxyServer
from core.utils import banners, get_ip, get_mac
from core.logger import logger
from core.plugincontainer import plugincontainer

print banners().get_banner()

if os.geteuid() != 0:
    sys.exit("[-] The derp is strong with this one")

parser = argparse.ArgumentParser(description="MITMf v0.9.8 - Framework for MITM attacks", version='0.9.8', usage='mitmf.py -i INTERFACE [mitmf options] [plugin/module name] [plugin/module options]', epilog="Use wisely, young Padawan.")
group = parser.add_argument_group("MITMf", "Options for MITMf")
group.add_argument('-i', dest='interface', required=True, help='Interface to bind to')
group.add_argument('--log-level', type=str,choices=['debug', 'info'], default="info", help="Specify a log level")
group.add_argument('--rport',dest='rport', metavar='PORT', type=int, default=10000, help="Regular proxy service port")
group.add_argument('--tport',dest='tport', metavar='PORT', type=int, default=10001, help="Transparent proxy service port")
group.add_argument('--ssl', dest='ssl', action='store_true', default=[r'.*:443'], help='Enable SSL/TLS interception')
group.add_argument('--preserve-cache', dest='preserve_cache', action='store_true', help="Don't kill client/server caching")

from plugins import *
#Get everything that inherits from the Plugin class
plugins = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]
plugincontainer().plugin_list = plugins

from modules import *
#Get everything that inherits from the Module class
modules = [module(parser) for module in module.Module.__subclasses__()]
plugincontainer().module_list = modules

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()
options.ip  = get_ip(options.interface)
options.mac = get_mac(options.interface)

logger().log_level = logging.__dict__[options.log_level.upper()]

print "[-] Initializing modules, plugins and servers"
for plugin in plugins:
    if vars(options)[plugin.optname] is True:
        print "|_ {} v{}".format(plugin.name, plugin.version)
        plugincontainer().activated_plugins.append(plugin)

for module in modules:
    if vars(options)[module.optname] is True:
        print "|_ {} v{}".format(module.name, module.version)
        plugincontainer().activated_modules.append(module)

from core.servers.dns.DNSchef import DNSChef
DNSChef().start()

from core.servers.smb.SMBserver import SMBserver
SMBserver().start()

if not options.ssl:
    options.ssl = []

from core.proxies.RegularProxy import RegularProxy
config = proxy.ProxyConfig(ignore_hosts=options.ssl, port=options.rport)
server = ProxyServer(config)
m = RegularProxy(server, options)
t = threading.Thread(name='regular-proxy', target=m.run)
t.setDaemon(True)
t.start()

from core.proxies.TransparentProxy import TransparentProxy
config = proxy.ProxyConfig(mode='spoof', ignore_hosts=options.ssl, port=options.tport)
server = ProxyServer(config)
m = TransparentProxy(server, options)
m.run()
