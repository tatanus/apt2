from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mynmap import mynmap

class scan_nmap_sslscan(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_sslscan, self).__init__(config, display, lock)
        self.title = "NMap SSL Scan"
        self.shortName = "NmapSSLScan"
        self.description = "execute [nmap --script ssl-ccs-injection,ssl-cert,ssl-date,ssl-dh-params," \
                           "ssl-enum-ciphers,ssl-google-cert-catalog,ssl-heartbleed,ssl-known-key,ssl-poodle," \
                           "sslv2] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newService_ssl", "newService_https", "newPort_tcp_443", "newPort_tcp_8443"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get(['port/tcp_443/ip', 'port/tcp_8443/ip', 'service/https', 'service/ssl'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        print(self.getTargets())
        # loop over each target
        for t in self.targets:
            print("HI")
            ports = kb.get(['service/https/' + t, 'service/ssl/host/' + t])
            for port in ports:
                print("1")
                # verify we have not tested this host before
                if not self.seentarget(t + str(port)):
                    print("1")
                    # add the new IP to the already seen list
                    self.addseentarget(t + str(port))
                    # run nmap
                    n = mynmap(self.config, self.display)
                    scan_results = n.run(target=t,
                                         flags="--script ssl-ccs-injection,ssl-cert,ssl-date,ssl-dh-params,"
                                               "ssl-enum-ciphers,ssl-google-cert-catalog,ssl-heartbleed,"
                                               "ssl-known-key,ssl-poodle,sslv2",
                                         ports=str(port), vector=self.vector, filetag=t + "_" + str(port) + "_SSLSCAN")
        return
