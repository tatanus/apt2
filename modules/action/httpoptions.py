import httplib

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class httpoptions(actionModule):
    def __init__(self, config, display, lock):
        super(httpoptions, self).__init__(config, display, lock)
        self.title = "Get HTTP Options"
        self.shortName = "httpOptions"
        self.description = "issue [OPTIONS / HTTP/1.0] to each web server"

        self.requirements = []
        self.triggers = ["newServicehttp", "newServicehttps", "newPort80", "newPort443"]
        self.types = ["http"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get(['service/http/host', 'service/https/host'])

    def processTarget(self, t, port):
        if not self.seentarget(t + str(port)):
            self.addseentarget(t + str(port))
            self.display.verbose(self.shortName + " - Connecting to " + t)
            try:
                conn = httplib.HTTPConnection(t, port, timeout=10)
                conn.request('OPTIONS', '/')
                response = conn.getresponse()
                text = ""
                allowed = response.getheader('allow')
                outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(
                    port) + "_" + Utils.getRandStr(10)
                if (allowed):
                    badoptions = ['PUT', 'DELETE', 'TRACE', 'TRACK']
                    for badopt in badoptions:
                        if (allowed.contains(badopt)):
                            self.fire("httpOption" + badopt)
                            self.addVuln(t, "httpOption" + badopt,
                                         {"port": str(port), "output": outfile.replace("/", "%2F")})
                            self.display.error("VULN [httpOption%s] Found on [%s:%i]" % (badopt, host, int(port)))
                    text = "Allowed HTTP Options for %s : %s\n\nFull Headers:\n%s" % (
                        t, allowed, self.print_dict(response.getheaders()))
                else:
                    text = "Allowed HTTP Options for %s : OPTIONS VERB NOT ALLOWED\n\nFull Headers:\n%s" % (
                        t, self.print_dict(response.getheaders()))
                Utils.writeFile(text, outfile)
            except httplib.BadStatusLine:
                pass
            # except socket.error as e:
            except:
                pass

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            ports = kb.get(['service/http/host/' + t + '/tcpport', 'service/https/host/' + t + '/tcpport'])
            for port in ports:
                self.processTarget(t, port)
                for hostname in self.getHostnames(t):
                    self.processTarget(hostname, port)

        return
