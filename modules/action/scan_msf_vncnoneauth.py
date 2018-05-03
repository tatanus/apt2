import re

from core.msfActionModule import msfActionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class scan_msf_vncnoneauth(msfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_vncnoneauth, self).__init__(config, display, lock)
        self.triggers = ["newPort_tcp_5900"]
        self.requirements = ["msfconsole"]
        self.title = "Detect VNC Services with the None authentication type"
        self.shortName = "MSFVNCNoneAuth"
        self.description = "execute [auxiliary/scanner/vnc_none_auth] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('port/tcp/5900')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # If any results are succesful, this will become true and Fire will be called in the end
            callFire = False
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)

                    cmd = {
                            'config':[
                                    "use auxiliary/scanner/vnc/vnc_none_auth",
                                    "set RHOSTS %s" % t
                                ],
                            'payload':'none'}
                    result, outfile = self.msfExec(t, cmds)


                    parts = re.findall(".*identified the VNC 'none' security type.*", result)
                    for part in parts:
                        callFire = True
                        self.addVuln(t, "VNCNoAuth", {"message": str(part), "output": outfile.replace("/", "%2F")})

            if callFire:
                self.Fire("vncAccess")

        return
