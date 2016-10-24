from core.actionModule import actionModule
from core.keystore import KeyStore as kb


class crackPasswordHashJohnTR(actionModule):
    def __init__(self, config, display, lock):
        super(crackPasswordHashJohnTR, self).__init__(config, display, lock)
        self.title = "Attempt to crack any password hashes"
        self.shortName = "CrackPasswordHashJTR"
        self.description = "execute john the ripper on each hash"

        self.requirements = ["john"]
        self.triggers = ["newPasswordHash"]
        self.types = ["hashcrack"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = kb.get('user/*/passwordhash')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # TODO
            # get list of all password hashes for current user
            # loop over each hash
            if not self.seentarget(t + h):
                # add the new IP to the already seen list
                self.addseentarget(t + h)
                # get the type of each hash (ntlm, lm, netntlmv2, etc..)
                # write each hach out to a temp file seperated by type (i.e. one file for all ntlm, one file for all
                # netntlmv2, etc...)

                # if any hashes were written to files
                # for each file
                # execute john on file
                # parse output of john and update kb with newly cracked passwords
        return
