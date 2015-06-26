'''
The base module class.
'''
import logging

from core.configwatcher import ConfigWatcher
from core.utils import logger_setup

class Module(ConfigWatcher, object):
    name      = ''
    optname   = ''
    desc      = ''
    version   = ''
    conflicts = []

    def __init__(self, parser):
        '''Passed the options namespace'''
        if self.desc:
            sgroup = parser.add_argument_group(self.name, self.desc)
        else:
            sgroup = parser.add_argument_group(self.name,"Options for the '{}' module".format(self.name))

        sgroup.add_argument("--{}".format(self.optname), action="store_true",help="Load module '{}'".format(self.name))

        self.module_options(sgroup)

    def initialize(self, context):
        '''Called when module is started'''
        formatter = logging.Formatter("%(asctime)s [{}] %(message)s".format(self.name), datefmt="%Y-%m-%d %H:%M:%S")
        self.logger  = logger_setup().setup_logger(self.name, formatter)
        self.options = context.options
        self.start_config_watch()

    def on_config_change(self):
        """Do something when MITMf detects the config file has been modified"""
        pass

    def module_options(self, options):
        '''Add your options to the options parser'''
        pass

    def on_shutdown(self, context):
        '''This will be called when shutting down'''
        pass
