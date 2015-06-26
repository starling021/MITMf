'''
The base plugin class. This shows the various methods that
can get called during the MITM attack.
'''
import argparse
import logging

from core.configwatcher import ConfigWatcher

class Plugin(ConfigWatcher, object):
    name    = "Generic plugin"
    optname = "generic"
    desc    = ""
    version = "0.0"

    def __init__(self, parser):
        '''Passed the options namespace'''
        if self.desc:
            sgroup = parser.add_argument_group(self.name, self.desc)
        else:
            sgroup = parser.add_argument_group(self.name,"Options for the '{}' plugin".format(self.name))

        sgroup.add_argument("--{}".format(self.optname), action="store_true",help="Load plugin '{}'".format(self.name))

        self.plugin_options(sgroup)

    def initialize(self, context):
        '''Called when plugin is started'''
        self.options = context.options
        self.start_config_watch()

    def request(self, context, flow):
        pass

    def responseheaders(self, context, flow):
        pass

    def response(self, context, flow):
        pass

    def on_config_change(self):
        """Do something when MITMf detects the config file has been modified"""
        pass

    def plugin_options(self, options):
        '''Add your options to the options parser'''
        pass

    def on_shutdown(self, context):
        '''This will be called when shutting down'''
        pass
