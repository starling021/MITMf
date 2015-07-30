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
import logging

from core.logger import logger
from core.plugincontainer import plugincontainer
from mitmflib.user_agents import parse
from libmproxy import controller
from libmproxy.protocol.http import decoded
from functools import wraps

formatter = logging.Formatter("%(asctime)s [RProxy] %(clientip)s [type:%(browser)s-%(browserv)s os:%(clientos)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logger().setup_logger('RegularProxy', formatter)

def concurrent(func):
    '''This makes all events concurrent (emulates the decorator in inline scripts)'''

    @wraps(func)
    def concurrent_func(*args, **kwargs):
        t = threading.Thread(name=func.func_name, target = func, args = args, kwargs = kwargs)
        t.start()
        return t

    return concurrent_func

class RegularProxy(controller.Master):

    def __init__(self, server, options):
        controller.Master.__init__(self, server)

        self.options     = options
        self.mode        = server.config.mode        
        self.clientinfo  = {}
        self.handle_post_output = False

        for key, value in vars(options).iteritems():
            setattr(self, key, value)

    def run(self):
        try:
            for plugin in called_plugins:
                plugin_hook = getattr(plugin, 'initialize')
                plugin_hook(self)

            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.handle_shutdown()
            self.shutdown()

    def log(self, message):
        log.info(message, extra=self.clientinfo)

    @concurrent
    def handle_request(self, flow):
        user_agent = parse(flow.request.headers['User-Agent'][0])
        
        self.clientinfo["clientip"] = flow.client_conn.address.host
        self.clientinfo["browser"]  = user_agent.browser.family
        self.clientinfo["clientos"] = user_agent.os.family
        try:
            self.clientinfo["browserv"] = user_agent.browser.version[0]
        except IndexError:
            self.clientinfo["browserv"] = "Other"

        del flow.request.headers['Cache-Control']

        del flow.request.headers['Accept-Encoding']

        if not options.preserve_cache:

            del flow.request.headers['If-Modified-Since']

            del flow.request.headers['If-None-Match']

            flow.request.headers['Pragma'] = ['no-cache']

        log.info("Sending request: {}".format(flow.request.host), extra=self.clientinfo)

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'request')
            plugin_hook(self, flow)

        if flow.request.method == "POST" and flow.request.content and (self.handle_post_output is False):
            log.info("POST Data ({}):\n{}".format(flow.request.host, flow.request.content), extra=self.clientinfo)

        self.handle_post_output = False

        flow.reply()

    @concurrent
    def handle_responseheaders(self, flow):
        if "Strict-Transport-Security" in flow.response.headers:
            del flow.response.headers["Strict-Transport-Security"]
            log.info("Zapped a Strict-Trasport-Security header for {}".format(flow.request.host), extra=self.clientinfo)

        if not options.preserve_cache:
            flow.response.headers['Expires'] = ["0"]
            flow.response.headers['Cache-Control'] = ["no-cache"]

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'responseheaders')
            plugin_hook(self, flow)

        flow.reply()

    @concurrent
    def handle_response(self, flow):

        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'response')
            plugin_hook(self, flow)

        flow.response.headers['Content-Length'] = [str(len(flow.response.content))]

        flow.reply()

    def handle_shutdown(self):
        for plugin in called_plugins:
            plugin_hook = getattr(plugin, 'on_shutdown')
            plugin_hook(self)

