import re
import sys
try:
    import whois
except ImportError:
    raise ImportError('Missing whois library. To install run: pip install whois')

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils

class apt2_whois(actionModule):
    def __init__(self, config, display, lock):
        super(apt2_whois, self).__init__(config, display, lock)
        self.title = "run whois"
        self.shortName = "Whois"
        self.description = "execute [whois] on each target"

        self.types = ["osint"]

        self.requirements = []
        self.triggers = ["newHostname", "newDomain"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get(['osint/hostname', 'osint/domain'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the to the already seen list
                self.addseentarget(t)
                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                result = whois.whois(t)
                Utils.writeFile(str(result), temp_file)
        return
