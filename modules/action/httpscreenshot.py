from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class httpscreenshot(actionModule):
    def __init__(self, config, display, lock):
        super(httpscreenshot, self).__init__(config, display, lock)
        self.title = "Get Screen Shot of Web Pages"
        self.shortName = "httpScreenShot"
        self.description = "load each web server and get a screenshot"

        self.requirements = ["phantomjs"]
        self.triggers = ["newServicehttp", "newServicehttps", "newPort80", "newPort443"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get(['service/http/host', 'service/https/host'])

    def processTarget(self, t, port):
        if not self.seentarget(t + str(port)):
            self.addseentarget(t + str(port))
            self.display.verbose(self.shortName + " - Connecting to " + t)
            outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(port) + "_" + Utils.getRandStr(
                10) + ".png"
            url = "http://" + t + ":" + str(port)
            Utils.webScreenCap(url, outfile)

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            ports = kb.get(['service/http/host/' + t + '/tcpport', 'service/https/host/' + t + '/tcpport'])
            for port in ports:
                self.processTarget(t, port)
                for hostname in self.getHostnames(t):
                    self.processTarget(hostname, port)

        return
