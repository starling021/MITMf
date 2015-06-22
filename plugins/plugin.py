'''
The base plugin class. This shows the various methods that
can get called during the MITM attack. 
'''
from core.configwatcher import ConfigWatcher
import logging

mitmf_logger = logging.getLogger('mitmf')

class Plugin(ConfigWatcher, object):
    name        = "Generic plugin"
    optname     = "generic"
    desc        = ""
    version     = "0.0"
    has_opts    = False

    def initialize(self, options):
        '''Called if plugin is enabled, passed the options namespace'''
        self.options = options

    def handle_clientconnect(self, context, handler):
        pass

    def handle_request(self, flow):
        pass

    def handle_serverconnect(self, context, handler):
        pass
        
    def handle_response(self, flow):
        pass

    def options(self, options):
        '''Add your options to the options parser'''
        pass

    def onShutdown(self):
        '''This will be called when shutting down'''
        pass
