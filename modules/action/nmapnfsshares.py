from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class nmapnfsshares(actionModule):
    def __init__(self, config, display, lock):
        super(nmapnfsshares, self).__init__(config, display, lock)
        self.title = "NMap NFS Share Scan"
        self.shortName = "NmapNFSShareScan"
        self.description = "execute [nmap -p2049 --script=nfs-ls,nfs-showmount] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort2049"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('host/*/tcpport/2049')

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
                scan_results = n.run(target=t, flags="--script=nfs-ls,nfs-showmount", ports="2049", vector=self.vector,
                                     filetag=t + "_NFSSHARESCAN")['scan']

                # TODO
                # parse output
        return
