import logging

from mitmflib.watchdog.observers import Observer
from mitmflib.watchdog.events import FileSystemEventHandler
from configobj import ConfigObj

logging.getLogger("watchdog").setLevel(logging.ERROR) #Disables watchdog's debug messages

logger = logging.getLogger('mitmf')

class ConfigWatcher(FileSystemEventHandler):

    @property
    def config(self):
        return ConfigObj("./config/mitmf.conf")

    def on_modified(self, event):
        logger.debug("[{}] Detected configuration changes, reloading!".format(self.name))
        self.on_config_change()

    def start_config_watch(self):
        observer = Observer()
        observer.schedule(self, path='./config', recursive=False)
        observer.start()

    def on_config_change(self):
        """ We can subclass this function to do stuff after the config file has been modified"""
        pass
