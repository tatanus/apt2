from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class nmapms08067scan(actionModule):
    def __init__(self, config, display, lock):
        super(nmapms08067scan, self).__init__(config, display, lock)
        self.title = "NMap MS08-067 Scan"
        self.shortName = "NmapMS08067Scan"
        self.description = "execute [nmap --script smb-vuln-ms08-067.nse -p445] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort445", "newPort139"]

        self.safeLevel = 4

    def getTargets(self):
        self.targets = kb.get(['host/*/tcpport/139', 'host/*/tcpport/445'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen list
                self.addseentarget(t)
                self.display.verbose(self.shortName + " - Connecting to " + t)
                # run nmap
                n = mynmap(self.config, self.display)
                scan_results = n.run(target=t, flags="--script smb-vuln-ms08-067.nse", ports="445", vector=self.vector,
                                     filetag=t + "_MS08067SCAN")['scan']
        return
