import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_smbuserenum(actionModule):
    def __init__(self, config, display, lock):
        super(msf_smbuserenum, self).__init__(config, display, lock)
        self.title = "Get List of Users From SMB"
        self.shortName = "MSFSMBUserEnum"
        self.description = "execute [auxiliary/scanner/smb/smb_enumusers] on each target"

        self.requirements = ["msfconsole"]
        self.triggers = ["nullSession"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that had nullsessions
        self.targets = kb.get('host/*/vuln/nullSession')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=self.config['msfport'], user=self.config['msfuser'],
                        password=self.config['msfpass'])

            if not msf.isAuthenticated():
                return

            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    self.display.verbose(self.shortName + " - Connecting to " + t)
                    msf.execute("use auxiliary/scanner/smb/smb_enumusers\n")
                    msf.execute("set RHOSTS %s\n" % t)
                    msf.execute("run\n")
                    msf.sleep(int(self.config['msfexploitdelay']))
                    result = msf.getResult()
                    while (re.search(".*execution completed.*", result) is None):
                        result = result + msf.getResult()

                    # MSF output format:[*] [timestamp] IP DOMAIN [user,users] ( extras)
                    parts = re.findall(".*" + t.replace(".", "\.") + ".*", result)
                    for part in parts:
                        if "RHOSTS" in part:
                            pass
                        else:
                            try:
                                pieces = part.split()
                                domain = pieces[3]
                                kb.add("domain/" + domain.strip() + "/host/" + t)
                                extras = part.split('(')[1].split(')')[0]
                                users = part.split('[')[3].split(']')[0].split(',')
                                for user in users:
                                    kb.add("host/" + t + "/user/" + user.strip())
                            except:
                                pass
                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                    Utils.writeFile(result, outfile)
                    kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))

            # clean up after ourselves
            result = msf.cleanup()

        return
