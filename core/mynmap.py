try:
    import nmap
except:
    sys.exit("[!] Install the nmap library: pip install python-nmap")

from core.events import EventHandler
from core.keystore import KeyStore as kb
from core.utils import Utils


class mynmap():
    def __init__(self, config, display):
        self.config = config
        self.display = display
        if not config:
            self.config = {}
        self.outfile = ""
        self.nm = nmap.PortScanner()

    def run(self, target="127.0.0.1", ports="1-1024", flags="-sS", vector="", filetag=""):
        # get tmp file
        proofsDir = ""
        if "proofsDir" in self.config.keys():
            proofsDir = self.config["proofsDir"]
        self.outfile = proofsDir + "NMAP-" + filetag + "-" + Utils.getRandStr(10)

        command = "nmap " + flags + " -p " + ports + " -oA " + self.outfile + " " + target
        tmp_results = Utils.execWait(command)
        self.display.output("Scan file saved to [%s]" % self.outfile)

        return self.loadXMLFile(self.outfile + ".xml", "nmapFile")

    def loadXMLFile(self, file, vector=""):
        results = dict()
        with open(file, "r") as fd:
            content = fd.read()
            results = self.nm.analyse_nmap_xml_scan(content)
            self.processIPs(vector)
        return results

    def getOutfile(self):
        return self.outFile

    def getIPs(self):
        return []

    def getPorts(self, host):
        return []

    def getResults(self):
        return []

    def processIPs(self, vector):
        for host in self.nm.all_hosts():
            # print host
            kb.add('host/' + host)
            # fire new event for "newHost"
            EventHandler.fire("newIP" + ":" + vector)

            # process ports
            self.processPorts(host, vector)

            # process hostscripts
            if ("hostscript" in self.nm[host]):
                self.processHostScripts(host, vector)
        return

    def processPorts(self, host, vector):
        for proto in self.nm[host].all_protocols():
            lport = list(self.nm[host][proto].keys())
            lport.sort()
            for port in lport:
                if (self.nm[host][proto][port]["state"] == "open"):
                    # fire event for "newPortXXX"
                    kb.add('host/' + host + '/' + proto + 'port/' + str(port))
                    # print  'host/' + host + '/' + proto + 'port/' + str(port)
                    EventHandler.fire("newPort" + str(port) + ":" + vector)

                    # process services and info
                    self.processService(host, port, proto, vector)
        return

    def processService(self, host, port, proto, vector):
        product = self.nm[host][proto][port]["product"]
        version = self.nm[host][proto][port]["version"]
        name = self.nm[host][proto][port]["name"]

        kb.add('service/' + name + '/host/' + host + '/' + proto + 'port/' + str(
            port) + '/product' + product + '/version/' + str(version))
        # print  'service/' + name + '/host/' + host + '/' + proto + 'port/' + str(port) + '/product' + product +
        # '/version/' + str(version)
        EventHandler.fire("newService" + str(name) + ":" + vector)
        if ("script" in self.nm[host][proto][port]):
            self.processScript(host, port, proto, vector)
        return

    def processScript(self, host, port, proto, vector):
        # print self.nm[host][proto][port]["script"]
        # print
        return

    def fireScriptVulnEvent(self, script_id, host, vector):
        # fire a new trigger
        EventHandler.fire(script_id + ":" + vector)
        kb.add('host/' + host + '/vuln/' + script_id)
        self.display.error("VULN [%s] Found on [%s]" % (script_id, host))

    def processHostScripts(self, host, vector):
        for script in self.nm[host]["hostscript"]:
            script_id = script["id"]
            output = script["output"]
            if script_id == "smb-vuln-ms08-067":
                script_id = "ms08-067"
                if "State: VULNERABLE" in output:
                    self.fireScriptVulnEvent(script_id, host, vector)
            elif script_id == "smb-security-mode":
                if "message_signing: disabled" in output:
                    self.fireScriptVulnEvent(script_id, host, vector)

    def out(self):
        return self.nm.get_nmap_last_output()
