try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class nmapnfsshares(actionModule):
    def __init__(self, config, display, lock):
        super(nmapnfsshares, self).__init__(config, display, lock)
        self.title = "NMap NFS Share Scan"
        self.shortName = "NmapNFSShareScan"
        self.description = "execute [nmap -p111 --script=nfs-ls,nfs-showmount] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort111"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('host/*/tcpport/111')

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
                scan_results = n.run(target=t, flags="--script=nfs-ls,nfs-showmount", ports="111", vector=self.vector,
                                     filetag=t + "_NFSSHARESCAN")['scan']

                tree = ET.parse(n.outfile + '.xml')
                root = tree.getroot()
                for volumestable in root.iter("table"):
                    if volumestable.attrib.has_key('key') and volumestable.attrib['key'] == "volumes":
                        for volume in volumestable:
                            sharename = ""
                            shareinfo = ""
                            files = {}
                            for elem in volume:
                                if elem.attrib["key"] == "volume":
                                    sharename = elem.text.replace("/", "%2F")
                                if elem.attrib["key"] == "info":
                                    shareinfo = elem[0].text.replace("/", "%2F")
                                if elem.attrib["key"] == "files":
                                    for file in elem:
                                        newfile = {}
                                        for fileprop in file:
                                            newfile[fileprop.attrib["key"]] = fileprop.text
                                        files[newfile["filename"]] = newfile
                            kb.add("host/" + t + "/shares/NFS/" + sharename + "/" + str("Info: " + shareinfo))
                            for file in files:
                                # TODO - Maybe revisit adding more file properties here in addition to names
                                kb.add("host/" + t + "/shares/NFS/" + sharename + "/Files/" + str(file).replace("/", "%2F"))
                                
        return
