from core.inputModule import inputModule
from core.keystore import KeyStore as kb
import re

class dictload(inputModule):
    def __init__(self, config, display, lock):
        super(dictload, self).__init__(config, display, lock)
        self.requirements = []
        self.title = "Load DICT Input File"
        self.description = "Load an DICT Input file"
        self.type = "dict"

    def process(self, inputfile):
        contents = []
        with open (inputfile, "r") as myfile:
            contents = myfile.readlines()

        for line in contents:
            parts = line.strip().split(':=')
            kb.add("osint/" + parts[0].lower() + "/" + parts[1])
            self.fire("new" + parts[0])
        return
