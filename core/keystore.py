import ast
try:
    from unqlite import UnQLite
except:
    sys.exit("[!] Install the UnQlite library: pip install unqlite") 

from utils import Utils

class KeyStore(object):
    db = UnQLite()

    # =================================================
    # "private" mathods
    # =================================================

    # get the list of values for a given key
    @staticmethod
    def _get(item):
        item = item.rstrip('/')
        values = list()

        # does the request contain a wild card value?
        if "/*/" in item:
            parts = item.split("*")
            left = parts[0].split()[-1]
            right = parts[1].split()[0] if parts[1].split() else ''

            temp_vals = KeyStore.get(left)
            if (isinstance(temp_vals, basestring)):
                temp_vals = ast.literal_eval(temp_vals)
            for temp_val in temp_vals:
                if left + temp_val + right in KeyStore.db:
                    values.append(temp_val)
        else:
            if item in KeyStore.db:
                values = KeyStore.db[item]

        return values

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
                values = KeyStore._get(key)
                if (isinstance(values, basestring)):
                    values = ast.literal_eval(values)
            if value not in values:
                values.append(value)
                KeyStore.db[key] = values
                KeyStore.add(key)

    # return a list of values for a given key
    @staticmethod
    def get(*items):
        result = list()

        for item in items:
            r2 = KeyStore._get(item)
            if (isinstance(r2, basestring)):
                r2 = ast.literal_eval(r2)
            result += r2
        if result:
            return sorted(set(result))
        return []

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

    # dump keystore to text
    @staticmethod
    def dump():
        dump = ""
        with KeyStore.db.cursor() as cursor:
            for key, values in cursor:
                values = ast.literal_eval(values)
                for value in values:
                    dump += "\n" + key + "/" + value
        return dump

    # save keystore to file
    @staticmethod
    def save(filename):
        Utils.writeFile(KeyStore.dump(), filename)
        return

    # load keystore from file
    @staticmethod
    def load(filename):
        lines = Utils.readFile(filename)
        for line in lines:
            KeyStore.add(line)
        return

# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print "-------------------------------------------------------------------"
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
    #KeyStore.debug()
    #print KeyStore.dump()

    print KeyStore.get("host/*/port/80")
    print KeyStore.get("host/2.2.2./port", "host/1.1.1.1/port")
    #print KeyStore.get("host")
#    KeyStore.add("service/http/host/1.1.1.1/tcpport/80/product/apache/version/1.1.1.1.1.1.1")
#    KeyStore.add("service/http/host/1.1.1.1/tcpport/8080/product/apache/version/1.1.1.3.3.3.3")
#    KeyStore.add("service/https/host/2.2.2.2/tcpport/443/product/nginx/version/a.b.c.d")
#    KeyStore.add("service/http/host/2.2.2.2/tcpport/80/product/nginx/version/a.b.c.d")
#    KeyStore.add("service/ssh/host/3.3.3.3/tcpport/22/product/openssh/version/q.w.e")
#    KeyStore.add("service/smtp/host/4.4.4.4/tcpport/25/product/sendmail/version/9.8.7.6")
#    print "-------------------------------------------------------------------"
#    KeyStore.debug()

#    print KeyStore.get("service")
