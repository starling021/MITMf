import logging
import sys
import threading
import os

from socket import error as socketerror
from mitmflib.impacket import version, smbserver, LOG
from core.servers.smb.KarmaSMB import KarmaSMBServer
from core.configwatcher import ConfigWatcher

class SMBserver(ConfigWatcher):

    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state

        self.impacket_ver = version.VER_MINOR
        self.server_type  = self.config["MITMf"]["SMB"]["type"].lower()
        self.smbchallenge = self.config["MITMf"]["SMB"]["Challenge"]
        self.smb_port     = int(self.config["MITMf"]["SMB"]["port"])

    def parseConfig(self):
        server = None
        try:
            if self.server_type == 'normal':

                formatter = logging.Formatter("%(asctime)s [SMB] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
                self.configureLogging(formatter)

                server = smbserver.SimpleSMBServer(listenPort=self.smb_port)
                
                for share in self.config["MITMf"]["SMB"]["Shares"]:
                    path = self.config["MITMf"]["SMB"]["Shares"][share]['path']
                    readonly = self.config["MITMf"]["SMB"]["Shares"][share]['readonly'].lower()
                    server.addShare(share.upper(), path, readOnly=readonly)

                server.setSMBChallenge(self.smbchallenge)
                server.setLogFile('')

            elif self.server_type == 'karma':

                formatter = logging.Formatter("%(asctime)s [KarmaSMB] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
                self.configureLogging(formatter)

                server = KarmaSMBServer(self.smbchallenge, self.smb_port)
                server.defaultFile = self.config["MITMf"]["SMB"]["Karma"]["defaultfile"]
                
                for extension, path in self.config["MITMf"]["SMB"]["Karma"].iteritems():
                    server.extensions[extension.upper()] = os.path.normpath(path)

            else:
                sys.exit("\n[-] Invalid SMB server type specified in config file!")

            return server
        
        except socketerror as e:
            if "Address already in use" in e:
                sys.exit("\n[-] Unable to start SMB server on port {}: port already in use".format(self.smb_port))

    def configureLogging(self, formatter):
        LOG.setLevel(logging.INFO)
        LOG.propagate = False
        logging.getLogger('smbserver').setLevel(logging.INFO)
        logging.getLogger('impacket').setLevel(logging.INFO)

        fileHandler = logging.FileHandler("./logs/mitmf.log")
        streamHandler = logging.StreamHandler(sys.stdout)
        fileHandler.setFormatter(formatter)
        streamHandler.setFormatter(formatter)
        LOG.addHandler(fileHandler)
        LOG.addHandler(streamHandler)

    def start(self):
        t = threading.Thread(name='SMBserver', target=self.parseConfig().start)
        t.setDaemon(True)
        t.start()
