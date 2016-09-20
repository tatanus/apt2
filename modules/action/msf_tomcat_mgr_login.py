import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_tomcat_mgr_login(actionModule):
    def __init__(self, config, display, lock):
        super(msf_tomcat_mgr_login, self).__init__(config, display, lock)
        self.triggers = ["newServicehttp", "newPort80", "newPort8080"]
        self.requirements = ["msfconsole"]
        self.title = "Attempt to determine if a tomcat instance has default creds"
        self.shortName = "MSFTomcatMgrLogin"
        self.description = "execute [auxiliary/scanner/http/tomcat_mgr_login] on each target"
        self.safeLevel = 4

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

            # loop over each target
            for t in self.targets:
                ports = kb.get('service/http/host/' + t + '/tcpport')
                for p in ports:
                    # verify we have not tested this host before
                    if not self.seentarget(t+p):
                        # add the new IP to the already seen list
                        self.addseentarget(t+p)
                        self.display.verbose(self.shortName + " - Connecting to " + t)
                        msf.execute("use auxiliary/scanner/http/tomcat_mgr_login\n")
                        msf.execute("set RHOSTS %s\n" % t)
                        msf.execute("set RPORT %s\n" % p)
                        msf.execute("run\n")
                        msf.sleep(int(self.config['msfexploitdelay']))

                        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                        result = msf.getResult()
                        Utils.writeFile(result, outfile)
                        kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"    ))
                        for line in result.splitlines():
                            m = re.match(r'.*SUCCESSFUL: (.*):(.*)', line)
                            if (m):
                                self.display.error("Tomcat on [" + t + ":" + p + "] has default creds of [" +
                                        m.group(1).strip() +"]/[" + m.group(2).strip() + "]")
                                kb.add("creds/host/" + t + "/port/" + p + "/service/tomcat/username/"
                                        + m.group(1).strip() + "/password/" + m.group(2).strip())
                                self.fire("newTomcatPassword")

            # clean up after ourselves
            result = msf.cleanup()

        return
