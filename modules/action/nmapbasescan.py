from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap
from core.utils import Utils


class nmapbasescan(actionModule):
    def __init__(self, config, display, lock):
        super(nmapbasescan, self).__init__(config, display, lock)
        self.title = "Standard NMap Scan"
        self.shortName = "NmapScan"
        self.description = "execute [nmap -sS] on each target"

        self.requirements = ["nmap", "disabled"]
        self.triggers = ["newIP"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get('host')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen list
                self.addseentarget(t)
                temp_file = self.config["proofsDir"] + Utils.getRandStr(10)

                # run nmap
                n = mynmap(self.config, self.diaplay)
                scan_results = n.run(target=t, flags="-sS -A", vector=self.vector)['scan']

                # loop over scan results and do anything you need
                #     fire any new triggers that are needed
                #     self.fire("TEST123")
                for host in scan_results.keys():
                    # loop over each proto and process it
                    for proto in ['tcp', 'udp']:
                        if (proto in scan_results[host]):
                            # loop over each proto and process it
                            for port in scan_results[host][proto].keys():
                                # only worry about open ports
                                if (scan_results[host][proto][port]["state"] == "open"):
                                    # fire event for "newPortXXX"
                                    self.fire("newPort" + str(port))
                                    kb.add('host/' + host + '/' + proto + 'port', port)
                                    # process services and info
                                    s = scan_results[host][proto][port]
                                    # print "%s - %i/%s (%s) \"%s %s\" [%s]" % (host, port, proto, s['name'],
                                    # s['product'], s['version'], s['extrainfo'])
                                    if (s['name'] == 'http') or (s['name'] == 'https'):
                                        self.fire('web')
                                    # check for any scripts and loop over them
                                    if ('script' in scan_results[host][proto][port].keys()):
                                        for script in scan_results[host][proto][port]['script'].keys():
                                            a = 1
                                            # print "     %s - [[%s]]" % (script, scan_results[host][proto][port][
                                            # 'script'][script])
        return
