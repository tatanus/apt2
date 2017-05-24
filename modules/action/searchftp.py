import fnmatch

try:
    import ftputil
except ImportError:
    raise ImportError('Missing ftputil library. To install run: pip install ftputil')

from core.actionModule import actionModule
from core.keystore import KeyStore as kb
from core.utils import Utils


class searchftp(actionModule):
    def __init__(self, config, display, lock):
        super(searchftp, self).__init__(config, display, lock)
        self.title = "Search files on FTP"
        self.shortName = "searchFTP"
        self.description = "connect to remote FTP service and search for interesting files"

        self.requirements = []
        self.triggers = ["newServiceftp", "newPort21"]
        self.types = ["filesearch"]

        self.safeLevel = 4

        self.filepatterns = self.config["file_search_patterns"].split(",")

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get('host/*/tcpport/21')
        self.targets2 = kb.get('service/ftp/host')

    def searchTarget(self, target, port, username, password):
        success = False
        # start packet capture
#        cap = self.pktCap(filter="tcp and port " + str(port) + " and host " + target, packetcount=10, timeout=10,
#                          srcip="", dstip=target)
        try:
            if (Utils.port_open(target, 21)):
                # attempt to connect to the remote host
                with ftputil.FTPHost(target, username, password) as host:
                    success = True
                    # get list of files and loop over them
                    recursive = host.walk("/", topdown=True, onerror=None)
                    for root, dirs, files in recursive:
                        for name in files:
                            for pattern in self.filepatterns:
                                match_list = fnmatch.filter(files, pattern)
                                for fname in match_list:
                                    fpath = host.path.join(root, fname)
                                    if host.path.isfile(fpath):
                                        host.download(fpath, self.config["proofsDir"] + ip + fpath.replace("/", "_"))
                    host.close()
        except ftputil.error.PermanentError:
            self.display.error("Could not connect to %s on port 21" % (target))

#        outfile = self.config["proofsDir"] + self.shortName + "_PCAP_Port" + str(port) + "_" + target + "_" + Utils.getRandStr(10)
#        Utils.writeFile(self.getPktCap(cap), outfile)
#        kb.add("host/" + target + "/files/" + self.shortName + "/" + outfile.replace("/", "%2F"))
        return success

    def testTarget(self, host, port):
        success = False
        # verify we have not tested this host before
        if not self.seentarget(host + str(port)):
            self.addseentarget(host + str(port))

            # test for anonumous ftp
            success = self.searchTarget(host, port, "anonymous", "anon@ymo.us")

            # test for user accounts
            if (not success):
                # get list of user creds for this host
                users = self.getUsers(host)
                # loop over each set of credentials
                for username in users:
                    passwords = kb.get('host/' + host + '/user/' + username + '/password')
                    for password in passwords:
                        if (searchTarget(host, port, username, password)):
                            return

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            self.testTarget(t, 21)
        for t in self.targets2:
            ports = kb.get('service/ftp/host/' + t + '/tcpport')
            for p in ports:
                self.testTarget(t, p)
        return
