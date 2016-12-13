import re
import sys
try:
    import shodan
except ImportError:
    raise ImportError('Missing shodan library. To install run: pip install shodan')

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils

class apt2_shodan(actionModule):
    def __init__(self, config, display, lock):
        super(apt2_shodan, self).__init__(config, display, lock)
        self.title = "run shodan"
        self.shortName = "Shodan"
        self.description = "execute [shodan] on each target"

        self.requirements = ["sslscan", "APIKEY"]
        self.triggers = ["newHost", "newDomainName", "newHostName"]

        self.safeLevel = 5
        self.targets2 = []

    def getTargets(self):
        self.targets = kb.get(['osint/domainname', 'osint/hostname'])
        self.targets2 = kb.get('osint/host')

    def shodan_query(self, query):
        max_attempts = 5

        shodan_api_object = shodan.Shodan(self.config['apt2_shodan_apikey'])
        finished = False
        i = 1;
        while not finished:
            if (i > max_attempts):
                print "Attempted to connect " + str(max_attempts) + " times and could not.   EXITING"
                break
            print "Attempting try #" + str(i)
            i = i + 1
            try:
                result = shodan_api_object.search(query=query, minify=True)
                outputtext = ""
                for t1 in result['matches']:
                    outputtext = outputtext + "\n" + result['ip_str'] + " " + str(result['port']) + "/" + result['transport'] + " (" + result['_shodan']['module'] + ")"
                finished = True
            except shodan.exception.APIError as e:
                if str(e) == "Unable to connect to Shodan":
                    finished = False
                    time.sleep(1)
                else:
                    print "Unhandled error occured: " + e
                    return None
        return outputtext


    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add to the already seen list
                self.addseentarget(t)
                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                result = self.shodan_query("hostname:"+t)
                Utils.writeFile(result, temp_file)

        # loop over each target
        for t in self.targets2:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add to the already seen list
                self.addseentarget(t)
                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                result = self.shodan_query("net:"+t)
                Utils.writeFile(result, temp_file)


        return
