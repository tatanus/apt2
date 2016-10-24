from core.actionModule import actionModule
from core.keystore import KeyStore as kb


class searchnfsshare(actionModule):
    def __init__(self, config, display, lock):
        super(searchnfsshare, self).__init__(config, display, lock)
        self.title = "Search files on NFS Shares"
        self.shortName = "searchFTP"
        self.description = "connect to remote NFS Share service and search for interesting files"

        self.requirements = ['disable']
        self.triggers = ["newServicenfs", "newPort2049"]
        self.types = ["filesearch"]

        self.safeLevel = 4

        self.filepatterns = self.config["file_search_patterns"].split(",")

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get('host/*/tcpport/2049')
        self.targets2 = kb.get('service/nfs/host/')

    def searchTarget(self, host, port, username, password):
        success = False
        # TODO
        # attempt to connect to the remote host
        #        th ftputil.FTPHost(host, username, password) as host:
        #            success = True
        #            # get list of files and loop over them
        #            recursive = host.walk("/",topdown=True,onerror=None)
        #            for root,dirs,files in recursive:
        #                for name in files:
        #                    for pattern in self.filepatterns:
        #                        match_list = fnmatch.filter(files, pattern)
        #                        for fname in match_list:
        #                            fpath = host.path.join(root, fname)
        #                            if host.path.isfile(fpath):
        #                                host.download(fpath, self.config["proofsDir"] + ip + fpath.replace("/", "_"))
        #        host.close()

        return success

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            True
            # get list of nfs shares on remote target
            # loop over shares
            # mount share
            # search share
        return
