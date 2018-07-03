import re

from core.msfActionModule import msfActionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class scan_msf_snmpenumusers(msfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_snmpenumusers, self).__init__(config, display, lock)
        self.triggers = ["snmpCred"]
        self.requirements = ["msfconsole"]
        self.title = "Enumerate Local User Accounts Using LanManager/psProcessUsername OID Values"
        self.shortName = "MSFSNMPEnumUsers"
        self.description = "execute [auxiliary/scanner/snmp/snmp_enumusers] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('vuln/host/*/snmpCred')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)

                    # Get list of working community strings for this host
                    comStrings = kb.get("vuln/host/" + t + "/snmpCred/communityString")
                    for comString in comStrings:
                        cmd = {
                                'config':[
                                        "use auxiliary/scanner/snmp/snmp_enumusers",
                                        "set RHOSTS %s" % t,
                                        "set COMMUNITY %s" % comString
                                    ],
                                'payload':'none'}
                        result, outfile = self.msfExec(t, cmds)

                        # Extract usernames from results and add to KB
                        parts = re.findall(".* users: .*", result)
                        for part in parts:
                            userlist = (part.split(':')[2]).split(',')
                            for username in userlist:
                                kb.add("creds/host/" + t + "/username/" + username.strip())

        return
