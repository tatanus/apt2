try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class scan_nmap_smbshares(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_smbshares, self).__init__(config, display, lock)
        self.title = "NMap SMB Share Scan"
        self.shortName = "NmapSMBShareScan"
        self.description = "execute [nmap -p445 --script smb-enum-shares] on each target"

        self.requirements = ["nmap", "disabled"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('port/tcp/139', 'port/tcp/445')

        for table in scan_results.iter('table'):
            sharename = table.attrib["key"]
            for elem in table:
                if elem.text is not None:
                    kb.add("share/smb/" + t + "/" + sharename + "/" + str(elem.attrib['key'] + ": " + elem.text).replace("/", "%2F"))

    def myProcessHostScript(self, host, script, outfile):
        outfile = outfile + ".xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if (scriptid == "smb-enum-shares"):
	    for table in script.findall('table'):
		for elem in table.findall('elem'):
                    if elem.attrib['key']:
                        None
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
            if writeAccess:
                self.addVuln(host, "nfs-write", {"port": "111", "output": outfile.replace("/", "%2F")})
                self.fire("nfsWrite")

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
                n = mynmap(self.config, self.display, hostScriptFunc=self.myProcessHostScript)
                scan_results = n.run(target=t, flags="--script smb-enum-shares", ports="445", vector=self.vector, filetag=t + "_SMBSHARESCAN")


        return
