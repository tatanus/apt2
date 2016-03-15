from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap


class nmapsslscan(actionModule):
    def __init__(self, config, display, lock):
        super(nmapsslscan, self).__init__(config, display, lock)
        self.title = "NMap SSL Scan"
        self.shortName = "NmapSSLScan"
        self.description = "execute [nmap --script ssl-ccs-injection,ssl-cert,ssl-date,ssl-dh-params," \
                           "ssl-enum-ciphers,ssl-google-cert-catalog,ssl-heartbleed,ssl-known-key,ssl-poodle," \
                           "sslv2] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newServicessl", "newServicehttps", "newPort443", "newPort8443"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get(['service/https/host', 'service/ssl/host'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            ports = kb.get(['service/https/host/' + t + '/tcpport', 'service/ssl/host/' + t + '/tcpport'])
            for port in ports:
                # verify we have not tested this host before
                if not self.seentarget(t + str(port)):
                    # add the new IP to the already seen list
                    self.addseentarget(t + str(port))
                    # run nmap
                    n = mynmap(self.config, self.display)
                    scan_results = n.run(target=t,
                                         flags="--script ssl-ccs-injection,ssl-cert,ssl-date,ssl-dh-params,"
                                               "ssl-enum-ciphers,ssl-google-cert-catalog,ssl-heartbleed,"
                                               "ssl-known-key,ssl-poodle,sslv2",
                                         ports=str(port), vector=self.vector, filetag=t + "_" + str(port) + "_SSLSCAN")[
                        'scan']
        return
