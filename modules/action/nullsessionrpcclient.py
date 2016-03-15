import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class nullsessionrpcclient(actionModule):
    def __init__(self, config, display, lock):
        super(nullsessionrpcclient, self).__init__(config, display, lock)
        self.title = "Test for NULL Session"
        self.shortName = "NULLSessionRpcClient"
        self.description = "execute [rpcclient -U \"\" -N <IP> -c srvinfo] on each target"

        self.requirements = ["rpcclient"]
        self.triggers = ["newPort445", "newPort139"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get(['host/*/tcpport/139', 'host/*/tcpport/445'])

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen list
                self.addseentarget(t)
                self.display.verbose(self.shortName + " - Connecting to " + t)
                # get windows domain/workgroup
                temp_file2 = self.config["proofsDir"] + "nmblookup_" + t + "_" + Utils.getRandStr(10)
                command2 = "nmblookup -A " + t
                result2 = Utils.execWait(command2, temp_file2)
                workgroup = "WORKGROUP"
                for line in result2.split('\n'):
                    m = re.match(r'\s+(.*)\s+<00> - <GROUP>.*', line)
                    if (m):
                        workgroup = m.group(1).strip()
                        self.display.debug("found ip [%s] is on the workgroup/domain [%s]" % (t, workgroup))

                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                # run rpcclient
                command = "rpcclient -N -U \"\" -W " + workgroup + " " + t + " -c srvinfo"
                result = Utils.execWait(command, temp_file)

                # check to see if it worked
                if any(x in result for x in ["NT_STATUS_LOGON_FAILURE", "NT_STATUS_ACCESS_DENIED"]):
                    # do nothing
                    self.display.verbose("Could not get NULL Session on %s" % t)
                else:
                    # fire a new trigger
                    self.fire("nullSession")

                    kb.add('host/' + t + '/vuln/nullSession')
                    self.display.error("VULN [NULLSession] Found on [%s]" % t)

                    # TODO - rpcclient srvinfo
                    # parse out put and store any new info and fire any additional triggers
        return
