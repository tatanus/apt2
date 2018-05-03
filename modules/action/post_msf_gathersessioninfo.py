import re
from core.msfActionModule import msfActionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class post_msf_gathersessioninfo(msfActionModule):
    def __init__(self, config, display, lock):
        super(post_msf_gathersessioninfo, self).__init__(config, display, lock)
        self.title = "Get Info about any new sessions"
        self.shortName = "MSFGatherSessionInfo"
        self.description = "execute [getuid] and [sysinfo] on any new msf sessions"

        self.requirements = ["msfconsole"]
        self.triggers = ["msfSession"]

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
                    # loop over each target
                    for s in sessions:
                        # verify we have not tested this session before
                        if not self.seentarget(s):
                            # add the new IP to the already seen list
                            self.addseentarget(s)

                            cmd = {
                                    'config':[
                                            "sessions -i %s" % str(s),
                                            "SLEEP",
                                            "getuid",
                                            "SLEEP",
                                            "background",
                                            "SLEEP"
                                        ],
                                    'payload':'none'}
                            result, outfile = self.msfExec(t, cmds)

                            for line in result.splitlines():
                                m = re.match(r'^\s*Server username: (.*)\s*', line)
                                if (m):
                                    self.display.verbose("Metasploit Session [" + s +
                                            "] running as user [" + m.group(1).strip() + "]")

                            cmd = {
                                    'config':[
                                            "sessions -i %s" % str(s),
                                            "SLEEP",
                                            "sysinfo",
                                            "SLEEP",
                                            "background",
                                            "SLEEP"
                                        ],
                                    'payload':'none'}
                            result, outfile = self.msfExec(t, cmds)


                            for line in result.splitlines():
                                m = re.match(r'^\s*OS\s\s*: (.*)\s*', line)
                                if (m):
                                    self.display.verbose("Metasploit Session [" + s +
                                            "] running on OS [" + m.group(1).strip() + "]")

        return
