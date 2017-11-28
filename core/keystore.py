import ast
from unqlite import UnQLite

from utils import Utils

class KeyStore(object):
    db = UnQLite()

    # =================================================
    # "private" mathods
    # =================================================
    
    # =================================================
    # "public" methods
    # =================================================

    # Set a new value within the keystore
    @staticmethod
    def add(item):
        item = item.rstrip('/')
        if (item not in KeyStore.db):
            KeyStore.db[item] = list()
        if (item.count('/') > 0):
            (key, value) = item.rsplit('/', 1)
            values = list()
            if key in KeyStore.db:
                values = KeyStore.get(key)
                values = ast.literal_eval(values)
            if value not in values:
                values.append(value)
                KeyStore.db[key] = values
                KeyStore.add(key)

    # return a list of values for a given key
    @staticmethod
    def get(item):
        item = item.rstrip('/')
        values = list()

        # does the request contain a wild card value?
        if "/*/" in item:
            parts = item.split("*")
            left = parts[0].split()[-1]
            right = parts[1].split()[0] if parts[1].split() else ''

            #(left, right) = item.split("*", 1)
            temp_vals = KeyStore.get(left)
            temp_vals = ast.literal_eval(temp_vals)
            for temp_val in temp_vals:
                if left + temp_val + right in KeyStore.db:
                    values.append(temp_val)
        else:
            if item in KeyStore.db:
                values = KeyStore.db[item]

        return values

    # remove a given key or value
    @staticmethod
    def rm(key):
        return

    # print out current KB
    @staticmethod
    def debug():
        with KeyStore.db.cursor() as cursor:
            for key, value in cursor:
                print key, '=>', value
        return

# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print "-------------------------------------------------------------------"
    KeyStore.debug()
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
    print "-------------------------------------------------------------------"
    KeyStore.debug()

    print KeyStore.get("host/*/port/80")
#    KeyStore.add("service/http/host/1.1.1.1/tcpport/80/product/apache/version/1.1.1.1.1.1.1")
#    KeyStore.add("service/http/host/1.1.1.1/tcpport/8080/product/apache/version/1.1.1.3.3.3.3")
#    KeyStore.add("service/https/host/2.2.2.2/tcpport/443/product/nginx/version/a.b.c.d")
#    KeyStore.add("service/http/host/2.2.2.2/tcpport/80/product/nginx/version/a.b.c.d")
#    KeyStore.add("service/ssh/host/3.3.3.3/tcpport/22/product/openssh/version/q.w.e")
#    KeyStore.add("service/smtp/host/4.4.4.4/tcpport/25/product/sendmail/version/9.8.7.6")
#    print "-------------------------------------------------------------------"
#    KeyStore.debug()

#    print KeyStore.get("service")
#    print KeyStore.get("service/smtp/host/4.4.4.4/tcpport/25/product/sendmail/version")
#    print json.dumps(kb, sort_keys=True, indent=4)

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
