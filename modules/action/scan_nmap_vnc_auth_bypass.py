try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class scan_nmap_vnc_auth_bypass(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_vnc_auth_bypass, self).__init__(config, display, lock)
        self.title = "NMap VNC Auth Bypass"
        self.shortName = "NmapVNCAuthBypass"
        self.description = "execute [nmap -p5800,5900 --script realvnc-auth-bypass] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_5800", "newPort_tcp_5900"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('port/tcp/5800', 'port/tcp/5900')

    def myProcessPortScript(self, host, proto, port, script, outfile):
        outfile = outfile + ".xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if scriptid == "realvnc-auth-bypass":
            for elem in script.iter('elem'):
                if elem.attrib['key'] == "state":
                    if elem.text == "VULNERABLE":
                        self.addVuln(host, "VNCNoAuth", {"message":"RealVNC 4.1.0 - 4.1.1 Authentication Bypass", "port":portnum})
                        self.Fire("vncAccess")

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
                scan_results = n.run(target=t, flags="--script realvnc-auth-bypass", ports="5800,5900", vector=self.vector, filetag=t + "_VNCAUTHBYPASS")

        return
