import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_snmpenumshares(actionModule):
    def __init__(self, config, display, lock):
        super(msf_snmpenumshares, self).__init__(config, display, lock)
        self.triggers = ["snmpCred"]
        self.requirements = ["msfconsole"]
        self.title = "Enumerate SMB Shares via LanManager OID Values"
        self.shortName = "MSFSNMPEnumShares"
        self.description = "execute [auxiliary/scanner/snmp/snmp_enumshares] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('host/*/vuln/snmpCred')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
                        password=self.config['msfpass'])

            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    self.display.verbose(self.shortName + " - Connecting to " + t)
                    # Get list of working community strings for this host
                    comStrings = kb.get("host/" + t + "/vuln/snmpCred")
                    for s in comStrings:
                        p = s.split()
                        comString = p[p.index("SUCCESSFUL:") + 1]
                        msf.execute("use auxiliary/scanner/snmp/snmp_enumshares\n")
                        msf.execute("set RHOSTS %s\n" % t)
                        msf.execute("set COMMUNITY %s\n" % comString)
                        msf.execute("run\n")
                        result = msf.getResult()
                        while (re.search(".*execution completed.*", result) is None):
                            result = result + msf.getResult()

                        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                        Utils.writeFile(result, outfile)

                        #  Don't need to parse out IP, we are running module one IP at a time
                        # Just find lines with  -  and pull out share name
                        parts = re.findall(".* - .*", result)
                        for part in parts:
                            sharename = (part.split('-')[0]).strip()
                            kb.add("host/" + t + "/smbShares/" + sharename)

            # clean up after ourselves
            result = msf.cleanup()

        return
