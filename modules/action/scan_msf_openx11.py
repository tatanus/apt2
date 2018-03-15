import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class scan_msf_openx11(actionModule):
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
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
                        password=self.config['msfpass'])

            if not msf.isAuthenticated():
                return

            # If any results are succesful, this will become true and Fire will be called in the end
            callFire = False
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    myMsf.lock.acquire()
                    self.display.verbose(self.shortName + " - Connecting to " + t)
                    msf.execute("use auxiliary/scanner/x11/open_x11\n")
                    msf.execute("set RHOSTS %s\n" % t)
                    msf.execute("exploit\n")
                    msf.sleep(int(self.config['msfexploitdelay']))
                    result = msf.getResult()
                    while (re.search(".*execution completed.*", result) is None):
                        result = result + msf.getResult()
                    myMsf.lock.release()

                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                    Utils.writeFile(result, outfile)

                    parts = re.findall(".*Open X Server.*", result)
                    for part in parts:
                        callFire = True
                        self.addVuln(t, "openX11",
                                     {"port": "6000", "message": str(part), "output": outfile.replace("/", "%2F")})

            # Nothing to trigger?
            if callFire:
                self.fire("x11Access")

            # clean up after ourselves
            result = msf.cleanup()

        return
