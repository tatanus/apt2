from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


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

                    # TODO
                    # print result

        return
