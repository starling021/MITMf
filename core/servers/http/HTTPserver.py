#!/usr/bin/env python2.7

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
import sys
import threading

from core.configwatcher import ConfigWatcher
from flask import Flask

class HTTPserver:

    _instance = None
    server = Flask(__name__)
    port = int(ConfigWatcher.getInstance().config['MITMf']['HTTP']['port'])

    @staticmethod
    def getInstance():
        if HTTPserver._instance is None:
            HTTPserver._instance = HTTPserver()

        return HTTPserver._instance

    def startFlask(self):
        self.server.run(host='0.0.0.0', port=self.port)

    def start(self):
        server_thread = threading.Thread(name='HTTPserver', target=self.startFlask)
        server_thread.setDaemon(True)
        server_thread.start()