from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_gathersessioninfo(actionModule):
    def __init__(self, config, display, lock):
        super(msf_gathersessioninfo, self).__init__(config, display, lock)
        self.title = "Get Info about any new sessions"
        self.shortName = "MSFGatherSessionInfo"
        self.description = "execute [getuid] and [sysinfo] on any new msf sessions"

        self.requirements = ["msfconsole"]
        self.triggers = ["msfSession"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested only in the hosts that had nullsessions
        self.targets = kb.get('host/*/msfSession')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        for t in self.targets:
            sessions = kb.get('host/' + t + '/msfSession')

            if len(sessions) > 0:
                # connect to msfrpc
                msf = myMsf(host=self.config['msfhost'], port=self.config['msfport'], user=self.config['msfuser'],
                            password=self.config['msfpass'])

                # loop over each target
                for s in sessions:
                    # verify we have not tested this session before
                    if not self.seentarget(s):
                        # add the new IP to the already seen list
                        self.addseentarget(s)
                        msf.execute("sessions -i " + str(s) + "\n")
                        msf.execute("getuid\n")
                        msf.execute("background\n")

                        # TODO
                        outfile = self.config["proofsDir"] + self.shortName + "_GetUid_" + t + "_" + Utils.getRandStr(
                            10)
                        text = msf.getResult()
                        Utils.writeFile(text, outfile)

                        msf.execute("sessions -i " + str(s) + "\n")
                        msf.execute("sysinfo\n")
                        msf.execute("background\n")

                        # TODO
                        outfile = self.config["proofsDir"] + self.shortName + "_SysInfo_" + t + "_" + Utils.getRandStr(
                            10)
                        text = msf.getResult()
                        Utils.writeFile(text, outfile)

            # clean up after ourselves
            result = msf.cleanup()

        return
