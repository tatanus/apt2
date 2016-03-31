import socket
from ftplib import FTP, error_perm

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class anonftp(actionModule):
    def __init__(self, config, display, lock):
        super(anonftp, self).__init__(config, display, lock)
        self.title = "Test for Anonymous FTP"
        self.shortName = "anonymousFTP"
        self.description = "connect to remote FTP service as anonymous"

        self.requirements = []
        self.triggers = ["newServiceftp", "newPort21"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get('host/*/tcpport/21')
        self.targets2 = kb.get('service/ftp/host')

    def testTarget(self, host, port):
        # verify we have not tested this host before
        if not self.seentarget(host + str(port)):
            self.addseentarget(host + str(port))
            self.display.verbose(self.shortName + " - Connecting to " + host)
            # start packet capture
            cap = self.pktCap(filter="tcp and port " + str(port) + " and host " + host, packetcount=10, timeout=10,
                              srcip=self.config['lhost'], dstip=host)

            # connect to the target host
            ftp = FTP()
            try:
                ftp.connect(host, int(port))

                outfile = self.config["proofsDir"] + self.shortName + "_PCAP_Port" + str(
                    port) + "_" + host + "_" + Utils.getRandStr(10)

                try:
                    # attempt to login as anonymous
                    result = ftp.login("anonymous", "anon@mo.us")
                    if ("Login successful" in result):
                        # fire a new trigger
                        self.fire("anonymousFtp")
                        self.addVuln(host, "anonymousFTP", {"port": str(port), "output": outfile.replace("/", "%2F")})
                        self.display.error("VULN [AnonymousFTP] Found on [%s]" % host)
                    else:
                        self.display.verbose("Could not login as anonymous to FTP at " + host)
                except error_perm as e:
                    self.display.verbose("Could not login as anonymous to FTP at " + host)

                # close the connection
                ftp.close()

                # retrieve pcap results
                Utils.writeFile(self.getPktCap(cap), outfile)
            except EOFError as e:
                self.display.verbose("Could not find FTP server located at " + host + " Port " + str(port))
            except socket.error as e:
                self.display.verbose("Could not find FTP server located at " + host + " Port " + str(port))

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            self.testTarget(t, 21)
        for t in self.targets2:
            ports = kb.get('service/ftp/host/' + t + '/tcpport')
            for p in ports:
                self.testTarget(t, p)
        return
