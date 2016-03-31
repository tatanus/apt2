import httplib

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class httpserverversion(actionModule):
    def __init__(self, config, display, lock):
        super(httpserverversion, self).__init__(config, display, lock)
        self.title = "Get HTTP Server Version"
        self.shortName = "HTTPServerVersion"
        self.description = "issue [GET / HTTP/1.0] to each web server"

        self.requirements = []
        self.triggers = ["newServicehttp", "newServicehttps", "newPort80", "newPort443"]

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

                conn.request('GET', '/')
                response = conn.getresponse()
                serverver = response.getheader('server')
                if (serverver):
                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(
                        port) + "_" + Utils.getRandStr(10)
                    Utils.writeFile("Identified Server Version of %s : %s\n\nFull Headers:\n%s" % (
                        t, serverver, self.print_dict(response.getheaders())), outfile)
                    kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))

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
