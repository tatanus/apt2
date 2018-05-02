import time
from multiprocessing.pool import ThreadPool

from core.events import EventHandler
from core.keystore import KeyStore as kb
from core.packetcap import pktcap

class actionModule(object):
    seentargets = dict()

    def __init__(self, config, display, lock):
        self.display = display
        self.config = config
        self.safeLevel = 1
        self.targets = []
        self.title = ""
        self.shortName = ""
        self.triggers = []
        self.requirements = []
        self.description = ""
        self.vector = ""
        self.lock = lock
        self.maxThreads = 100
        self.types = []

    def getTitle(self):
        return self.title

    def getDescription(self):
        return self.description

    def getSafeLevel(self):
        return self.safeLevel

    def getTriggers(self):
        return self.triggers

    def getRequirements(self):
        return self.requirements

    def getTypes(self):
        return self.types

    def getShortName(self):
        return self.shortName

    def getTargets(self):
        return None

    def getMaxThreads(self):
        return self.maxThreads

    def getVector(self):
        return self.vector

    def process(self):
        return

    def go(self, vector):
        self.vector = vector
        self.display.verbose("-> Running : " + self.getTitle())
        self.display.debug("---> " + self.getDescription())
        return self.process()

    def fire(self, trigger):
        EventHandler.fire(trigger + ":" + self.vector + "-" + self.shortName)

    def getVectorDepth(self):
        return len(self.vector.split('-'))

    def pktCap(self, filter="", packetcount=10, timeout=60, srcip="", dstip=""):
        pool = ThreadPool(processes=1)
        p = pktcap()

        # create new thread/process for the packet capture
        async_result = pool.apply_async(p.capture, (filter, timeout, packetcount, srcip, dstip,))

        # slepp for a second to allow everything to get set up
        time.sleep(1)

        return async_result

    def getPktCap(self, obj):
        if (obj):
            return obj.get()
        return ""

    def addseentarget(self, target):
        self.lock.acquire()

        if not self.getShortName() in actionModule.seentargets:
            actionModule.seentargets[self.getShortName()] = list()

        if not target in actionModule.seentargets[self.getShortName()]:
            actionModule.seentargets[self.getShortName()].append(target)
        self.lock.release()

    def seentarget(self, target):
        self.lock.acquire()

        # set default value
        value = False
        # check if "shortname" is a key in seentargets
        if self.getShortName() in actionModule.seentargets:
            # check if target is an element in the list
            if target in actionModule.seentargets[self.getShortName()]:
                value = True

        self.lock.release()

        return value

    def print_dict(self, d):
        string = ""
        for key, value in d:
            string += "%s: %s\n" % (key, value)
        return string

    def getDomainUsers(self, domain):
        return kb.get('creds/domain/' + domain + '/username/')

    def getUsers(self, host):
        return kb.get('creds/host/' + host + '/username/')

    def getHostnames(self, host):
        return kb.get('host/' + host + '/hostname/')

    def addVuln(self, host, vuln, details={}):
        self.display.error("VULN [%s] Found on [%s]" % (vuln,host))
        kb.add("vuln/host/" + host + "/" + vuln + "/module/" + self.shortName + "/" + self.vector)
        for key in details:
            kb.add("vuln/host/" + host + "/" + vuln + "/details/" + key + "/" + details[key])
