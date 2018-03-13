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

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('port/tcp/139', 'port/tcp/445')

    def myProcessHostScript(self, host, script, outfile):
        outfile = outfile + ".xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if (scriptid == "smb-enum-shares"):
            for volumes in script.findall("table"):
                for volume in volumes:
                    readAccess = False
                    writeAccess = False
                    sharename = ""
                    sharetype = ""
                    sharecomment = ""
                    anonaccess = ""
                    useraccess = ""
    
                    files = {}
                    sharename = volume.attrib["key"]
                    for elem in volume:
                        if elem.attrib["key"] == "Type":
                            sharetype = elem.text.replace("/", "%2F")
                        if elem.attrib["key"] == "Comment":
                            sharecomment = elem.text.replace("/", "%2F")
                        elif elem.attrib["key"] == "Anonymous access":
                            rights = elem[0].text
                            if "READ" in rights:
                                readAccess = True
                            if "WRITE" in rights:
                                writeAccess = True
                            anonaccess = rights.replace("/", "%2F")
                        elif elem.attrib["key"] == "Current user access":
                            rights = elem[0].text
                            if "READ" in rights:
                                readAccess = True
                            if "WRITE" in rights:
                                writeAccess = True
                            useraccess = rights.replace("/", "%2F")
                    kb.add("share/smb/" + sharename + "/" + host + "/" + str("Info: " + anonaccess))
    
                if readAccess:
                    self.addVuln(host, "smb-read", {"port": "445", "output": outfile.replace("/", "%2F")})
                    self.fire("nfsRead")
                if writeAccess:
                    self.addVuln(host, "smb-write", {"port": "445", "output": outfile.replace("/", "%2F")})
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
