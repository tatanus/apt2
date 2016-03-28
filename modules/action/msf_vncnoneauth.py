import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_vncnoneauth(actionModule):
    def __init__(self, config, display, lock):
        super(msf_vncnoneauth, self).__init__(config, display, lock)
        self.triggers = ["newPort5900"]
        self.requirements = ["msfconsole"]
        self.title = "Detect VNC Services with the None authentication type"
        self.shortName = "MSFVNCNoneAuth"
        self.description = "execute [auxiliary/scanner/vnc_none_auth] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('host/*/tcpport/5900')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
                        password=self.config['msfpass'])

            # If any results are succesful, this will become true and Fire will be called in the end
            callFire = False
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    self.display.verbose(self.shortName + " - Connecting to " + t)
                    msf.execute("use auxiliary/scanner/vnc/vnc_none_auth\n")
                    msf.execute("set RHOSTS %s\n" % t)
                    msf.execute("run\n")
                    result = msf.getResult()
                    while (re.search(".*execution completed.*", result) is None):
                        result = result + msf.getResult()

                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                    Utils.writeFile(result, outfile)

                    parts = re.findall(".*identified the VNC 'none' security type.*", result)
                    for part in parts:
                        callFire = True
                        self.addVuln(t, "VNCNoAuth",{"message":str(part)})

            if callFire:
                self.Fire("vncAccess")

            # clean up after ourselves
            result = msf.cleanup()

        return
