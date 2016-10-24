import re
import sys

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class sslsslscan(actionModule):
    def __init__(self, config, display, lock):
        super(sslsslscan, self).__init__(config, display, lock)
        self.title = "Determine SSL protocols and ciphers"
        self.shortName = "SSLTestSSLScan"
        self.description = "execute [sslscan <server>:<port> on each target"

        self.requirements = ["sslscan"]
        self.triggers = ["newServicessl", "newServicehttps", "newPort443", "newPort8443"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get(['service/https/host', 'service/ssl/host'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            ports = kb.get(['service/https/host/' + t + '/tcpport', 'service/ssl/host/' + t + '/tcpport'])
            for port in ports:
                # verify we have not tested this host before
                if not self.seentarget(t + str(port)):
                    # add the new IP to the already seen list
                    self.addseentarget(t + str(port))
                    # make outfile
                    temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(
                        port) + "_" + Utils.getRandStr(10)

                    command = self.config["sslscan"] + " --no-color " + t + ":" + port
                    result = Utils.execWait(command, temp_file, timeout=60)
                    depricatedlist = []
                    weakciphers = []
                    keystrength = ""
                    with open (temp_file, "r") as myfile:
                        result=myfile.readlines()

                    for line in result:
                        m = re.match(r'^\s*Accepted\s\s+([^ ]*)\s\s*(\d\d*)\s\s*bits\s*([^ ]*)', line)
                        if (m):
                            protocol = m.group(1).strip()
                            bit = m.group(2).strip()
                            cipher = m.group(3).strip()
                            if (protocol == "SSLv2"):
                                if protocol not in depricatedlist:
                                    depricatedlist.append(protocol)
                            elif (protocol == "SSLv3"):
                                if protocol not in depricatedlist:
                                    depricatedlist.append(protocol)
                            elif (protocol == "TLSv1.0"):
                                if protocol not in depricatedlist:
                                    depricatedlist.append(protocol)
                            elif (protocol == "TLSv1.1"):
                                if protocol not in depricatedlist:
                                    depricatedlist.append(protocol)
                            elif (protocol == "TLSv1.2"):
                                if "DES" in cipher:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                                elif "RSA" in cipher:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                                elif "NULL" in cipher:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                                elif int(bit) < 112:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                        else:
                            m = re.match(r'^\s*RSA Key Strength:\s*(\d\d*)', line)
                            if (m):
                                if int(m.group(1).strip()) < 2048:
                                    keystrength = m.group(1).strip()

                    # store data into KB
                    for depricatedProto in depricatedlist:
                       kb.add('service/https/host/' + t + '/tcpport/' + port + '/depricatedSSLProto/' + depricatedProto)
                    for weakCipher in weakciphers:
                       kb.add('service/https/host/' + t + '/tcpport/' + port + '/weakSSLCipher/' + weakCipher)
                    if keystrength is not "":
                       kb.add('service/https/host/' + t + '/tcpport/' + port + '/weakSSLKeyStrength/' + keystrength)

                    # improve the output
                    self.display.debug(t + "," + str(port) + "," + ' '.join(depricatedlist) + "," + ' '.join(
                        weakciphers) + "," + keystrength)

        return
