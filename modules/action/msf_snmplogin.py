import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_snmplogin(actionModule):
    def __init__(self, config, display, lock):
        super(msf_snmplogin, self).__init__(config, display, lock)
        self.triggers = ["newPort161"]
        self.requirements = ["msfconsole"]
        self.title = "Attempt Login Using Common Community Strings"
        self.shortName = "MSFSNMPLogin"
        self.description = "execute [auxiliary/scanner/snmp/snmp_login] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('host/*/udpport/161')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
                        password=self.config['msfpass'])

            if not msf.isAuthenticated():
                return

            # If any results are succesful, this will become true and Fire will be called in the end
            callFire = False
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    self.display.verbose(self.shortName + " - Connecting to " + t)
                    msf.execute("use auxiliary/scanner/snmp/snmp_login\n")
                    msf.execute("set RHOSTS %s\n" % t)
                    msf.execute("set VERSION 2c\n")
                    msf.execute("run\n")
                    msf.sleep(int(self.config['msfexploitdelay']))
                    result = msf.getResult()
                    while (re.search(".*execution completed.*", result) is None):
                        result = result + msf.getResult()

                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                    Utils.writeFile(result, outfile)

                    parts = re.findall(".*LOGIN SUCCESSFUL.*", result)
                    for part in parts:
                        callFire = True
                        # Add all relevant details
                        p = part.split()
                        comString = p[p.index("SUCCESSFUL:") + 1]
                        self.addVuln(t, "snmpCred", {"port": "161", "message": str(part), "communityString": comString,
                                                     "output": outfile.replace("/", "%2F")})

            if callFire:
                self.fire("snmpCred")

            # clean up after ourselves
            result = msf.cleanup()

        return
