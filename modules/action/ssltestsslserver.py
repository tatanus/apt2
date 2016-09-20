from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils
import re


class ssltestsslserver(actionModule):
    def __init__(self, config, display, lock):
        super(ssltestsslserver, self).__init__(config, display, lock)
        self.title = "Determine SSL protocols and ciphers"
        self.shortName = "SSLTestSSLServer"
        self.description = "execute [TestSSLServer <server> <port>] on each target"

        self.requirements = ["java"]
        self.triggers = ["newServicehttps", "newServicessl", "newPort443", "newPort8443"]

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

                    command = "java -jar " + self.config["miscDir"] + "TestSSLServer.jar " + t + " " + port
                    result = Utils.execWait(command, temp_file, timeout=30)

                    depricatedlist = []
                    weakciphers = []
                    keystrength = ""
                    tls12 = False
                    with open (temp_file, "r") as myfile:
                        result=myfile.readlines()

                    for line in result:
                        if (tls12):
                            m = re.match(r'^    (.*))', line)
                            if (m):
                                cipher = line.strip()
                                if "DES" in cipher:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                                elif "RSA" in cipher:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                                elif "NULL" in cipher:
                                    if cipher not in weakciphers:
                                        weakciphers.append(cipher)
                            else:
                                tls12 = False

                        else:
                            m = re.match(r'^\s*Supported versions: (.*)', line)
                            if (m):
                                if ("SSLv2" in m.group(1)):
                                    protocol = "SSLv2"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                                elif ("SSLv3" in m.group(1)):
                                    protocol = "SSLv3"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                                elif ("TLSv1.0" in m.group(1)):
                                    protocol = "TLSv1.0"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                                elif ("TLSv1.1" in m.group(1)):
                                    protocol = "TLSv1.1"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                            m = re.match(r'^  TLSv1.2\s*', line)
                            if (m):
                                tls12 = True

                    # store data into KB
                    for depricatedProto in depricatedlist:
                       kb.add('service/https/host/' + t + '/tcpport/' + port + '/depricatedSSLProto/' + depricatedProto)
                    for weakCipher in weakciphers:
                       kb.add('service/https/host/' + t + '/tcpport/' + port + '/weakSSLCipher/' + weakCipher)
                    if keystrength is not "":
                       kb.add('service/https/host/' + t + '/tcpport/' + port + '/weakSSLKeyStrength/' + keystrength)


        return
