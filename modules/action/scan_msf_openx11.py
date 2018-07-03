import re

from core.msfActionModule import msfActionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class scan_msf_openx11(msfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_openx11, self).__init__(config, display, lock)
        self.triggers = ["newPort_tcp_6000"]
        self.requirements = ["msfconsole"]
        self.title = "Attempt Login To Open X11 Service"
        self.shortName = "MSFOpenX11"
        self.description = "execute [auxiliary/scanner/x11/open_x11] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have TCP 6000 open
        self.targets = kb.get('port/tcp/6000')

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
                                    "use auxiliary/scanner/x11/open_x11",
                                    "set RHOSTS %s" % t
                                ],
                            'payload':'none'}
                    result, outfile = self.msfExec(t, cmds)

                    parts = re.findall(".*Open X Server.*", result)
                    for part in parts:
                        callFire = True
                        self.addVuln(t, "openX11",
                                     {"port": "6000", "message": str(part), "output": outfile.replace("/", "%2F")})

            # Nothing to trigger?
            if callFire:
                self.fire("x11Access")

        return
