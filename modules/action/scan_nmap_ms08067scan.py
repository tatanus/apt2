from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap

class scan_nmap_ms08067scan(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_ms08067scan, self).__init__(config, display, lock)
        self.title = "Nmap MS08-067 Scan"
        self.shortName = "NmapMS08067Scan"
        self.description = "execute [nmap --script smb-vuln-ms08-067.nse -p445] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 4

    def getTargets(self):
        self.targets = kb.get('port/tcp_139/ip', 'port/tcp_445/ip')

    def myProcessHostScript(self, host, script, outfile):
        outfile = outfile + ".xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if (scriptid == "smb-vuln-ms08-067"):
            for table in script.findall('table'):
                for elem in table.findall('elem'):
                    if elem.attrib['key'] == "state":
                        if ("VULNERABLE" in elem.text) or ("INFECTED" in elem.text):
                            self.addVuln(host, "smb-vuln-ms08-067", {"port": "445", "output": outfile.replace("/", "%2F")})
                            self.fire("ms08-067")
                            self.display.error("VULN [MS08-067] Found on [%s]" % host)

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
                scan_results = n.run(target=t, flags="--script smb-vuln-ms08-067.nse", ports="445", vector=self.vector, filetag=t + "_MS08067SCAN")
        return
