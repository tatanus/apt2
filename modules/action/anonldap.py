import re
from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class anonldap(actionModule):
    def __init__(self, config, display, lock):
        super(anonldap, self).__init__(config, display, lock)
        self.title = "Test for Anonymous LDAP Searches"
        self.shortName = "AnonymousLDAP"
        self.description = "execute [ldapsearch -h <server> -p 389 -x -s base"

        self.requirements = ["ldapsearch"]
        self.triggers = ["newServiceldap", "newPort389"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get(['host/*/tcpport/389', 'host/*/udpport/389'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        callFire = False
        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                self.display.verbose(self.shortName + " - Connecting to " + t)
                # add the new IP to the already seen list
                self.addseentarget(t)
                # make outfile
                outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                # run rpcclient
                command = self.config["ldapsearch"] + " -h " + t + " -p 389 -x -s base"
                result = Utils.execWait(command, outfile)

                # TODO - Parse output and do stuff
                parts = re.findall("ref: .*", result)
                for part in parts:
                    callFire = True
                    self.addVuln(t, "AnonymousLDAP", {"port": "389", "message": str(part).replace("/", "%2F"), "output": outfile.replace("/", "%2F")})
        if callFire:
                self.fire("anonymousLDAP")

        return
