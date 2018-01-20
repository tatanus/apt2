try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class scan_nmap_vncbrute(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_vncbrute, self).__init__(config, display, lock)
        self.title = "NMap VNC Brute Scan"
        self.shortName = "NmapVNCBruteScan"
        self.description = "execute [nmap -p5800,5900 --script=vnc-brute] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_5800", "newPort_tcp_5900"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('port/tcp_5800/ip', 'port/tcp_5900/ip')

    def myProcessPortScript(self, host, proto, port, script, outfile):
        outfile = outfile + ".xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if scriptid == "vnc-brute":
            if "No authentication required" in output:
                self.addVuln(host, "VNCNoAuth", {"port":port,"message":"No authentication required","output": outfile.replace("/", "%2F")})
                self.fire("VNCNoAuth")
            for elem in script.iter('elem'):
                if elem.attrib['key'] == "password":
                    self.addVuln(host, "VNCBrutePass", {"port":portnum, "password":elem.text})
                    self.fire("VNCBrutePass")

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
                scan_results = n.run(target=t, flags="--script=vnc-brute", ports="5800,5900", vector=self.vector, filetag=t + "_VNCBRUTE")

        return
