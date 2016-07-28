import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class snmpwalk(actionModule):
    def __init__(self, config, display, lock):
        super(snmpwalk, self).__init__(config, display, lock)
        self.triggers = ["snmpCred"]
        self.requirements = ["snmpwalk"]
        self.title = "Run snmpwalk using found community string"
        self.shortName = "SNMPWalk"
        self.description = "execute [snmpwalk -v 2c -c COMMUNITY ip] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have working snmp community strings
        self.targets = kb.get('host/*/vuln/snmpCred')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # loop over each target
            for t in self.targets:
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    cstrings = kb.get("host/" + t + "/vuln/snmpCred/communityString")
                    for community in cstrings:
                        command = "snmpwalk -v 2c -c " + community + " " + t
                        result = command + "\n" + Utils.execWait(command) #append command to top of output
                        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                        Utils.writeFile(result, outfile)
                        kb.add("host/" + t + "/vuln/snmpCred/output/" + outfile.replace("/", "%2F"))

        return
