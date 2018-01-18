import sys
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from core.events import EventHandler
from core.keystore import KeyStore as kb
from core.utils import Utils

class mynmap():
    def __init__(self, config, display, hostScriptFunc=None, portScriptFunc=None):
        self.config = config
        self.display = display
        if not config:
            self.config = {}

        self.hostScriptFunc = hostScriptFunc
        if not hostScriptFunc:
            self.hostScriptFunc = self.processHostScript
        self.portScriptFunc =portScriptFunc
        if not portScriptFunc:
            self.portScriptFunc = self.processScript

        self.outfile = ""
        self.vector = ""

    def run(self, target="127.0.0.1", ports="1-1024", flags="-sS", vector="", filetag=""):
        proofsDir = ""
        if "proofsDir" in self.config.keys():
            proofsDir = self.config["proofsDir"]
        filetag = filetag.replace("/", "_").replace(" ", "_")
        self.outfile = proofsDir + "NMAP-" + filetag + "-" + Utils.getRandStr(10)
        
        command = self.config["nmap"] + " " + flags + " -p " + ports + " -oA " + self.outfile + " " + target
        tmp_results = Utils.execWait(command)
        self.display.output("Scan file saved to [%s]" % self.outfile)

        return self.loadXMLFile(self.outfile + ".xml")

    def loadXMLFile(self, file, vector=""):
        self.vector = vector
        tree = ET.parse(file)
        self.processXML(tree)
        root = tree.getroot()
        return root

    def getOutfile(self):
        return self.outfile

    def processXML(self, tree):
        for host in tree.iter('host'):
            if host.find('status').attrib['state'] == 'up':
                hostip = self.processHost(host)
                if host.find('os'):
                    self.processOs(hostip, host.find('os'))
                for hostscript in host.findall('hostscript'):
                    for script in hostscript.findall('script'):
                        self.hostScriptFunc (hostip, script)
                if host.find('ports'):
                    for port in host.find('ports').findall('port'):
                        self.processPort(hostip, port)

    def processHost(self, host):
        ip = ""
        for addr in host.findall('address'):
            ip_tmp = addr.attrib['addr']
            addrType = addr.attrib['addrtype']
            if addrType == "ipv4":
                ip = ip_tmp
                kb.add('host/' + ip)
                EventHandler.fire("newIP" + ":" + self.vector)
        if host.find('hostname'):
            for hostname in host.find('hostnames').findall('hostname'):
                name = hostname.attrib['name']
                kb.add('host/' + ip + '/dns/' + name)
        return ip
    
    def processOs(self, host, os):
        osStr = ""
        osStrAcc = 0
        for osmatch in os.findall('osmatch'):
            osStr_tmp = osmatch.attrib['name'] if osmatch.attrib['name'] else ""
            osStrAcc_tmp = osmatch.attrib['accuracy'] if osmatch.attrib['accuracy'] else ""
            if (int(osStrAcc_tmp) > osStrAcc):
                osStrAcc = int(osStrAcc_tmp)
                osStr = osStr_tmp
        osFam = ""
        osGen = ""
        osClassAcc = 0
        for osclass in os.findall('osclass'):
#            print osclass.attrib['type']
#            print osclass.attrib['vendor']
            osFam_tmp = osclass.attrib['osfamily'] if osclass.attrib['osfamily'] else ""
            osGen_tmp = osclass.attrib['osgen'] if osclass.attrib['osgen'] else ""
            osClassAcc_tmp = osclass.attrib['accuracy'] if osclass.attrib['accuracy'] else ""
            if (int(osClassAcc_tmp) > osClassAcc):
                osClassAcc = int(osClassAcc_tmp)
                osFam = osFam_tmp
                osGen = osGen_tmp
        kb.add('host/' + host + '/os/' + osFam + ' ' + osGen)
    
    def processPort(self, host, port):
        state = port.find('state').attrib['state']
        if state == "open":
            portnum = port.attrib['portid']
            proto = port.attrib['protocol']
            kb.add('port/' + proto + '_' + portnum + '/ip/' + host)
            EventHandler.fire("newPort_" + proto + '_' + portnum + ":" + self.vector)

            self.processService(host, portnum, proto, port.find('service'))
    
            for script in port.findall('script'):
                self.portScriptFunc (host, portnum, proto, script)
    
    def processService(self, host, port, proto, service):
        name = ""
        product = ""
        version = ""
        for key, value in service.attrib.items():
            if   key == 'name':
                name = value
            elif key == 'product':
                product = value
            elif key == 'version':
                version = value
#            elif key == 'ostype':
#                print value
#            elif key == 'method':
#                print value
#            elif key == 'conf':
#                print value
        kb.add('service/' + name + '/' + host + '/' + proto + '_' + port + '/version/' + product + ' ' + version)
        EventHandler.fire("newService_" + name + ":" + self.vector)
    
    def processHostScript(self, host, script):
#        print script.attrib['id']
#        print script.attrib['output']
#        for child in script:
#            print child.tag
#            print child.text
#            print child.attrib
        return
    
    def processScript(self, host, port, proto, script):
#        print script.attrib['id']
#        print script.attrib['output']
#        for child in script:
#            print child.tag
#            print child.text
#            print child.attrib
        return
