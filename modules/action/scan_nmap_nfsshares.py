try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap

class scan_nmap_nfsshares(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_nfsshares, self).__init__(config, display, lock)
        self.title = "NMap NFS Share Scan"
        self.shortName = "NmapNFSShareScan"
        self.description = "execute [nmap -p111 --script=nfs-ls,nfs-showmount] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_udp_111", "newPort_tcp_111"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('port/tcp_111/ip', 'port/udp_111/ip')

    def myProcessPortScript(self, host, proto, port, script, outfile):
        outfile = outfile + ".xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if (scriptid == "nfs-ls"):
            readAccess = False
            writeAccess = False
            for volumes in script.findall("table"):
                for volume in volumes.findall("table"):
                    sharename = ""
                    shareinfo = ""
                    files = {}
                    for elem in volume:
                        if elem.attrib["key"] == "volume":
                            sharename = elem.text.replace("/", "%2F")
                        if elem.attrib["key"] == "info":
                            rights = elem[0].text
                            if "Read" in rights:
                                readAccess = True
                            if "Modify" in rights:
                                writeAccess = True
                            shareinfo = rights.replace("/", "%2F")
                        if elem.attrib["key"] == "files":
                            for file in elem:
                                newfile = {}
                                for fileprop in file:
                                    newfile[fileprop.attrib["key"]] = fileprop.text
                                files[newfile["filename"]] = newfile
                    kb.add("share/nfs/" + sharename + "/" + host + "/" + str("Info: " + shareinfo))
#                    for file in files:
#                        # TODO - Maybe revisit adding more file properties here in addition to names
#                        kb.add("host/" + host + "/shares/NFS/" + sharename + "/Files/" + str(file).replace("/", "%2F"))
#                        print ("host/" + host + "/shares/NFS/" + sharename + "/Files/" + str(file).replace("/", "%2F"))

            if readAccess:
                self.addVuln(host, "nfs-read", {"port": "111", "output": outfile.replace("/", "%2F")})
                self.fire("nfsRead")
                self.display.error("VULN [NFS Share - Read Access] Found on [%s]" % host)
            if writeAccess:
                self.addVuln(host, "nfs-write", {"port": "111", "output": outfile.replace("/", "%2F")})
                self.fire("nfsWrite")
                self.display.error("VULN [NFS Share - Write Access] Found on [%s]" % host)

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
                n = mynmap(self.config, self.display, portScriptFunc=self.myProcessPortScript)
                scan_results = n.run(target=t, flags="--script=nfs-ls,nfs-showmount", ports="111", vector=self.vector, filetag=t + "_NFSSHARESCAN")

                                
        return
