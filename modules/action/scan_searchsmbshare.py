#import fnmatch
import re

try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    raise ImportError('Missing pysmb library. To install run: pip install pysmb')

from core.actionModule import actionModule
from core.keystore import KeyStore as kb


class scan_searchsmbshare(actionModule):
    def __init__(self, config, display, lock):
        super(scan_searchsmbshare, self).__init__(config, display, lock)
        self.title = "Search files on SMB Shares"
        self.shortName = "searchSMB"
        self.description = "connect to remote SMB Share service and search for interesting files"

        self.requirements = []
        self.triggers = ["newServicen_smb", "newPort_tcp_445", "newPort_tcp_139"]
        self.types = ["filesearch"]

        self.safeLevel = 4

        self.filepatterns = self.config["file_search_patterns"].split(",")

    def getTargets(self):
        # we are interested in all hosts
        self.targets = kb.get('port/tcp/445', 'port/tcp/139')
        self.targets2 = kb.get('service/smb')

    def searchTarget(self, host, username, password, domainname):
        success = False

        try:
            self.display.debug('### Analyzing system: ' + host)
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
            connected = conn.connect(host, 445)
            if connected:
                success = True

                try:
                    Response = conn.listShares(timeout=30)  # obtain a list of shares
                    self.display.debug('Shares on: ' + host)
                    for i in range(len(Response)):  # iterate through the list of shares
                        self.display.debug("  Share[" + str(i) + "] =" + str(Response[i].name))
                        try:
                            # list the files on each share (recursivity?)
                            Response2 = conn.listPath(Response[i].name, '/', timeout=30)
                            self.display.debug('    Files on: ' + host + '/' + "  Share[" + str(i) + "] =" + str(Response[i].name))
                            for i in range(len(Response2)):
                                for pattern in self.filepatterns:
                                    try:
                                        re.compile(pattern)
                                        result = re.match(pattern, Response2[i].filename)
                                        if (result):
                                            # TODO
                                            # host.download(fpath, self.config["proofsDir"] + ip + fpath.replace("/", "_"))
                                            self.display.debug("    File[" + str(i) + "] =" + str(Response2[i].filename))
                                    except re.error:
                                        self.display.debug("Invalid File Pattern --> %s <--" % pattern) 
                        except:
                            self.display.error('### can not access the resource')
                except:
                    self.display.error('### can not list shares')
        except:
            self.display.error('### can not access the system (%s) (%s) (%s) (%s)' % (host, username, password, domainname))

        return success

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # test for NULL authentication first
            if not self.seentarget(t):
                self.addseentarget(t)
                self.searchTarget(t, '', '', '')

            # test for any local users
            for user in self.getUsers(t):
                passwords = kb.get(['creds/host/' + t + '/username/' + user + '/password'])
                for password in passwords:
                    if not self.seentarget(t + user + password):
                        self.addseentarget(t + user + password)
                        self.searchTarget(t, user, password, "")

            # test for any domain users
            domains = kb.get("host/" + t + "/domain")
            for domain in domains:
                for user in self.getDomainUsers(domain):
                    passwords = kb.get(['creds/domain/' + t + '/username/' + user + '/password'])
                    for password in passwords:
                        if not self.seentarget(t + user + password + domain):
                            self.addseentarget(t + user + password + domain)
                            self.searchTarget(t, user, password, domain)
        return
