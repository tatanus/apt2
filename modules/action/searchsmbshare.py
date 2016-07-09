import fnmatch

try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    raise ImportError('Missing pysmb library. To install run: pip install pysmb')

from core.actionModule import actionModule
from core.keystore import KeyStore as kb


class searchsmbshare(actionModule):
    def __init__(self, config, display, lock):
        super(searchsmbshare, self).__init__(config, display, lock)
        self.title = "Search files on SMB Shares"
        self.shortName = "searchFTP"
        self.description = "connect to remote NFS Share service and search for interesting files"

        # self.requirements = ['disable']
        self.requirements = []
        self.triggers = ["newServicensmb", "newPort445", "newPort139"]

        self.safeLevel = 4

        self.filepatterns = ['.bat', '*.sh', '*passwd*', '*password*', '*Pass*', '*.conf', '*.cnf', '*.cfg', '*.config']

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get(['host/*/tcpport/445', 'host/*/tcpport/139'])
        self.targets2 = kb.get('service/smb/host')

    def searchTarget(self, host, username, password, domainname):
        success = False

        try:
            self.display.debug('### Analyzing system: ' + system_name)
            # parameterize an smb connection with a system
            conn = SMBConnection(username,
                                 password,
                                 'enumerator',
                                 host,
                                 domainname,
                                 use_ntlm_v2=True,
                                 sign_options=SMBConnection.SIGN_WHEN_SUPPORTED,
                                 is_direct_tcp=True)

            # establish the actual connection
            connected = conn.connect(system_name, 445)
            success = True

            try:
                Response = conn.listShares(timeout=30)  # obtain a list of shares
                self.display.debug('Shares on: ' + system_name)
                for i in range(len(Response)):  # iterate through the list of shares
                    self.display.debug("  Share[", i, "] =", Response[i].name)
                    try:
                        # list the files on each share (recursivity?)
                        Response2 = conn.listPath(Response[i].name, '/', timeout=30)
                        self.display.debug('    Files on: ' + system_name + '/' + "  Share[", i, "] =",
                                           Response[i].name)
                        for i in range(len(Response2)):
                            for pattern in self.filepatterns:
                                match_list = fnmatch.filter(Response2[i].filename, pattern)
                                for fname in match_list:
                                    # host.download(fpath, self.config["proofsDir"] + ip + fpath.replace("/", "_"))
                                    self.display.debug("    File[", i, "] =", Response2[i].filename)
                    except:
                        self.display.error('### can not access the resource')
            except:
                self.display.error('### can not list shares')
        except:
            self.display.error('### can not access the system')

        return success

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            True
        # get domain name for target
        # get username/password for the target
        # get list of smb shares on remote target
        # loop over shares
        # search share
        return
