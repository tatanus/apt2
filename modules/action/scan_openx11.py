import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class scan_openx11(actionModule):
    def __init__(self, config, display, lock):
        super(scan_openx11, self).__init__(config, display, lock)
        self.triggers = ["newPort_tcp_6000"]
        self.requirements = ["xwd", "convert"]
        self.title = "Attempt Login To Open X11 Servicei and Get Screenshot"
        self.shortName = "OpenX11"
        self.description = "execute [xwd -root -screen -silent -display <SYSTEM IP>:0 | convert - <SYSTEM IP>.png] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have TCP 6000 open
        self.targets = kb.get('port/tcp/6000')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # loop over each target
            for t in self.targets:
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)

                    command = self.config["xwd"] + " -root -screen -silent -display " + t + ":0"
                    result = Utils.execWait(command)
                    if "unable to open display" not in result:
                        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10) + ".png"
                        command = self.config["xwd"] + " -root -screen -silent -display " + t + ":0 | convert - " + outfile
                        self.addVuln(t, "openX11",
                                {"port": "6000", "output": outfile.replace("/", "%2F")})

                        self.fire("x11Access")

        return
