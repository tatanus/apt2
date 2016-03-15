import json
from collections import defaultdict

from utils import Utils


class Tree(defaultdict):
    def __init__(self, parent=None):
        self.parent = parent
        defaultdict.__init__(self, lambda: Tree(self))


class KeyStore(object):
    store = Tree()

    # =================================================
    # "private" mathods
    # =================================================

    # Set a new value within the keystore
    @staticmethod
    def _add(path=None):
        # return [] if path is empty
        if (not path):
            return

        t = KeyStore.store
        for node in path:
            t = t[node]
        return

    # return a list of values for a given key
    @staticmethod
    def _get(path):
        # return [] if path is empty
        if (not path):
            return []

        # set t to the KeyStore.store to begin
        t = KeyStore.store

        # set up left part of path and right part of path
        lpath = ""
        rpath = "/".join(path)

        for node in path:
            # update right path
            rpath = rpath[len(node) + 1:]

            # if the node is a wildcard, process it
            if (node == "*"):
                result = []
                for k in t.keys():
                    tmp_path = lpath + "/" + str(k) + "/" + rpath
                    if (KeyStore._test(tmp_path.split('/'))):
                        result = result + [str(k)]

                return result

            # else check to see if the current node is in the keys of the previous node
            if (node in t.keys()):
                # if so, update tree to point to the proper place
                t = t[node]
            else:
                return []

            # if left path is not empty, then append a / to it
            if lpath != "":
                lpath += "/"

            # add current node to left path
            lpath += node

        # return results
        return t.keys()

    # test to see if a given path exists
    @staticmethod
    def _test(path):
        # return [] if path is empty
        if (not path):
            return False

        # set t to the KeyStore.store to begin
        t = KeyStore.store

        # set up left part of path and right part of path
        lpath = ""
        rpath = "/".join(path)

        for node in path:
            # update right path
            rpath = rpath[len(node) + 1:]

            # else check to see if the current node is in the keys of the previous node
            if (node in t.keys()):
                # if so, update tree to point to the proper place
                t = t[node]
            else:
                return False

            # if left path is not empty, then append a / to it
            if lpath != "":
                lpath += "/"

            # add current node to left path
            lpath += node

        # return results
        return True

    # remove a given key or value
    @staticmethod
    def _rm(path):
        # return [] if path is empty
        if (not path):
            return

        t = KeyStore.store
        fnode = path[len(path) - 1]
        for node in path[:len(path) - 1]:
            if node in t.keys():
                t = t[node]
            else:
                return

        if (fnode in t.keys()):
            del t[fnode]

        return

    # helps with pretty printing
    @staticmethod
    def _dicts(t):
        return {k: KeyStore._dicts(t[k]) for k in t}

    # =================================================
    # "public" methods
    # =================================================

    # Set a new value within the keystore
    @staticmethod
    def add(key):
        return KeyStore._add(key.split('/'))

    # return a list of values for a given key
    @staticmethod
    def get(key):
        result = []
        # are we processin just one lookup?
        if (isinstance(key, basestring)):
            result = KeyStore._get(key.split('/'))
        # or are we processing 2 lookups?
        elif (isinstance(key, list)):
            for k in key:
                r2 = KeyStore.get(k)
                result = result + r2
        return sorted(set(result))

    # remove a given key or value
    @staticmethod
    def rm(key):
        return KeyStore._rm(key.split('/'))

    # print out the keystore
    @staticmethod
    def debug(kb=None):
        if (kb == None):
            kb = KeyStore.store
        print json.dumps(kb, sort_keys=True, indent=4)

    # print out the keystore
    @staticmethod
    def xml(kb=None, indent=0):
        xml = ""
        if (kb == None):
            kb = KeyStore.store
        for elm in kb:
            if (len(kb[elm]) == 0):
                xml = xml + (indent * "  ") + elm + "\n"
            else:
                xml = xml + (indent * "  ") + "<" + elm + ">\n"
                xml = xml + KeyStore.xml(kb[elm], indent + 1)
                xml = xml + (indent * "  ") + "</" + elm + ">\n"

        return xml

    # save the keystore to a file
    @staticmethod
    def save(filename):
        # pickle.dump( KeyStore.store, open( filename, "wb" ) )
        Utils.writeFile(KeyStore.xml(), filename)
        return

    # load the keystore from a file
    @staticmethod
    def load(filename):
        # KeyStore.store = pickle.load( open( filename, "rb" ) )
        return


# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    #    KeyStore.debug()
    #    KeyStore.add("host/1.2.3.4/port/111")
    #    KeyStore.add("host/a.b.c.d/port/80")
    #    KeyStore.add("host/a.b.c.d/port/80/bob")
    #    KeyStore.add("host/a.b.c.d/port/80/apple")
    #    KeyStore.add("host/a.b.c.d/port")
    #    KeyStore.add("host/a.b.c.d/port/443")
    KeyStore.add("host/1.1.1.1/port/80")
    KeyStore.add("host/1.1.1.1/port/8080")
    KeyStore.add("host/2.2.2.2/port/443")
    KeyStore.add("host/2.2.2.2/port/80")
    KeyStore.add("host/3.3.3.3/port/22")
    KeyStore.add("host/4.4.4.4/port/25")

    KeyStore.add("service/http/host/1.1.1.1/tcpport/80/product/apache/version/1.1.1.1.1.1.1")
    KeyStore.add("service/http/host/1.1.1.1/tcpport/8080/product/apache/version/1.1.1.3.3.3.3")
    KeyStore.add("service/https/host/2.2.2.2/tcpport/443/product/nginx/version/a.b.c.d")
    KeyStore.add("service/http/host/2.2.2.2/tcpport/80/product/nginx/version/a.b.c.d")
    KeyStore.add("service/ssh/host/3.3.3.3/tcpport/22/product/openssh/version/q.w.e")
    KeyStore.add("service/smtp/host/4.4.4.4/tcpport/25/product/sendmail/version/9.8.7.6")

    kb = KeyStore.get("service")
    print json.dumps(kb, sort_keys=True, indent=4)

# print "=========  PORT 80  ========="
#    print " SHOULD BE 1.1.1.1 2.2.2.2"
#    kb=KeyStore.get("host/*/port/80")
#    print json.dumps(kb, sort_keys=True, indent=4)
#    print "=========  PORT 443  ========="
#    print " SHOULD BE 2.2.2.2"
#    kb=KeyStore.get("host/*/port/443")
#    print json.dumps(kb, sort_keys=True, indent=4)
#    print "=========  PORT 8080  ========="
#    print " SHOULD BE 1.1.1.1"
#    kb=KeyStore.get("host/*/port/8080")
#    print json.dumps(kb, sort_keys=True, indent=4)
#    print "=========  SERVICE HTTP  ========="
#    print " SHOULD BE 1.1.1.1 2.2.2.2"
#    kb=KeyStore.get("service/http/host")
#    print json.dumps(kb, sort_keys=True, indent=4)
#    print "=========  SERVICE HTTPS  ========="
#    kb=KeyStore.get("service/https/host")
#    print " SHOULD BE 2.2.2.2"
#    print json.dumps(kb, sort_keys=True, indent=4)
#
#    print "=========  PORT 80 and SERVICE HTTP  ========="
#    print " SHOULD BE 1.1.1.1 2.2.2.2"
#    kb=KeyStore.get(["service/http/host", "host/*/port/80"])
#    print json.dumps(kb, sort_keys=True, indent=4)
##    for t in kb:
##        print
##        print t
##        kb2 = KeyStore.get('service/http/host/' + t + '/tcpport')
##        print json.dumps(kb2, sort_keys=True, indent=4)
#
#    print "=========  PORT 443 and SERVICE HTTPS  ========="
#    print " SHOULD BE 2.2.2.2"
#    kb=KeyStore.get(["service/https/host", "host/*/port/443"])
#    print json.dumps(kb, sort_keys=True, indent=4)
##    for t in kb:
##        print
##        print t
##        kb2 = KeyStore.get('service/https/host/' + t + '/tcpport')
##        print json.dumps(kb2, sort_keys=True, indent=4)
#
##    KeyStore.debug(kb=KeyStore.get("host/*/port"))
#    #KeyStore.rm("host/a.b.c.d/port/80")
#    #KeyStore.debug(kb=KeyStore.get("host/*/port"))
##    kb=KeyStore.get(["host/*/port/80", "host/*/port/111"])
##    KeyStore.debug(kb=KeyStore.get("host/*/port/80"))
##    KeyStore.debug(kb=KeyStore.get("host/*/port/111"))
##    kb=KeyStore.get(["host/*/port/111"])
#
##    print "-----------------------------"
##    kb=KeyStore.get("host/a.b.c.d/port")
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get("host/a.b.c.d/port/80")
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get("host/a.b.c.d/port/80/apple")
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get("host/a.b.c.d/port/80/dog")
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get(["host/a.b.c.d/port/80/apple"])
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get(["host/*/port/80"])
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get(["host/*/port/111"])
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get(["host/*/port/80", "host/*/port/111"])
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
##    kb=KeyStore.get(["host/*/port/80/apple"])
##    print json.dumps(kb, sort_keys=True, indent=4)
##    print "-----------------------------"
#
##    KeyStore.debug(kb = kb)
##    for t in kb:
##        print t
##        print kb[t]
##    KeyStore.debug()
#    KeyStore.save("out.save")
##    KeyStore.xml()
#    #KeyStore.debug()
#    #KeyStore.load("out.save")
#    #KeyStore.debug()
