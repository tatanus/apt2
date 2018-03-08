import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class scan_msf_jboss_vulnscan(actionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_jboss_vulnscan, self).__init__(config, display, lock)
        self.triggers = ["newServicehttp", "newPort80", "newPort8080"]
        self.requirements = ["msfconsole"]
        self.types = ["http"]
        self.title = "Attempt to determine if a jboss instance has default creds"
        self.shortName = "MSFJbossVulnscan"
        self.description = "execute [auxiliary/scanner/http/jboss_vulnscan] on each target"
        self.safeLevel = 4

    def getTargets(self):
        self.targets = kb.get('port/tcp/443', 'port/tcp/8443', 'service/https', 'service/ssl')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'], password=self.config['msfpass'])

            if not msf.isAuthenticated():
                return

            # loop over each target
            for t in self.targets:
                ports = kb.get('service/http/' + t + '/tcp')
                for p in ports:
                    # verify we have not tested this host before
                    if not self.seentarget(t+p):
                        # add the new IP to the already seen list
                        self.addseentarget(t+p)
                        self.display.verbose(self.shortName + " - Connecting to " + t)
                        msf.execute("use auxiliary/scanner/http/jboss_vulnscan\n")
                        msf.execute("set RHOSTS %s\n" % t)
                        msf.execute("set RPORT %s\n" % p)
                        msf.execute("exploit -j\n")
                        msf.sleep(int(self.config['msfexploitdelay']))

                        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                        result = msf.getResult()
                        Utils.writeFile(result, outfile)
                        kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"    ))
                        for line in result.splitlines():
                            m = re.match(r'.*Authenticated using (.*):(.*)', line)
                            if (m):
                                self.display.error("Jboss on [" + t + ":" + p + "] has default creds of [" +
                                        m.group(1).strip() +"]/[" + m.group(2).strip() + "]")
                                kb.add("creds/service/jboss/" + t + "/port/" + p + "/username/"
                                        + m.group(1).strip() + "/password/" + m.group(2).strip())
                                self.fire("newJbossPassword")

            # clean up after ourselves
            result = msf.cleanup()

        return
