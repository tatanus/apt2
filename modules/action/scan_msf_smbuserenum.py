import re

from core.msfActionModule import msfActionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class scan_msf_smbuserenum(msfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_smbuserenum, self).__init__(config, display, lock)
        self.title = "Get List of Users From SMB"
        self.shortName = "MSFSMBUserEnum"
        self.description = "execute [auxiliary/scanner/smb/smb_enumusers] on each target"

        self.requirements = ["msfconsole"]
        self.triggers = ["nullSession"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that had nullsessions
        self.targets = kb.get('vuln/host/*/nullSession')

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

                    cmd = {
                            'config':[
                                    "use auxiliary/scanner/smb/smb_enumusers",
                                    "set RHOSTS %s" % t
                                ],
                            'payload':'none'}
                    result, outfile = self.msfExec(t, cmds)

                    # MSF output format:[*] [timestamp] IP DOMAIN [user,users] ( extras)
                    parts = re.findall(".*" + t.replace(".", "\.") + ".*", result)
                    for part in parts:
                        if "RHOSTS" in part:
                            pass
                        else:
                            try:
                                pieces = part.split()
                                domain = pieces[3]
                                kb.add("host/" + t + "/domain/" + domain.strip())
                                extras = part.split('(')[1].split(')')[0]
                                users = part.split('[')[3].split(']')[0].split(',')
                                for user in users:
                                    kb.add("creds/host/" + t + "/username/" + user.strip())
                            except:
                                pass
                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                    Utils.writeFile(result, outfile)
                    kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))

        return
