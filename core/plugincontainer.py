
class plugincontainer:

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

        self.options = None
        self.plugin_list = []
        self.activated_plugins = []
        self.module_list = []
        self.activated_modules = []

    def load_plugins(self, plugins):
        pass

    def load_modules(self, modules):
        pass
