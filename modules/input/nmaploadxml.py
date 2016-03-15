from core.inputModule import inputModule
from core.mynmap import mynmap


class nmaploadxml(inputModule):
    def __init__(self, config, display, lock):
        super(nmaploadxml, self).__init__(config, display, lock)
        self.requirements = ["nmap"]
        self.title = "Load NMap XML File"
        self.description = "Load an NMap XML file"
        self.type = "nmap"

    def process(self, inputfile):
        n = mynmap(self.config, self.display)
        n.loadXMLFile(inputfile, "nmapFile")
        return
