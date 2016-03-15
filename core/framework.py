import argparse
import imp
import os
import re
import sys

# import our libs
from utils import Utils, Display
from keystore import KeyStore as kb
from events import EventHandler
from mynmap import mynmap
from mymsf import myMsf
from threading import RLock, Thread


class Framework():
    def __init__(self):
        self.display = Display()
        self.modulelock = RLock()

        self.inputModules = {}
        self.actionModules = {}

        self.progName = "APT2"
        self.version = "error"
        self.isRunning = True  # Conditional to check if user wants to quit

        self.inputs = {}

        self.config = {}

        self.config["outDir"] = os.getcwd() + "/"
        self.config["reportDir"] = ""
        self.config["logDir"] = ""
        self.config["proofsDir"] = ""
        self.config["tmpDir"] = ""
        self.config["miscDir"] = ""
        self.config['lhost'] = Utils.getIP()

        self.setupDirs()

        # initialize some config options
        self.config["config_filename"] = ""

        # default all bool values to False
        self.config["verbose"] = False
        self.config["always_yes"] = False
        self.config["list_modules"] = False

        self.config["scan_target"] = None
        self.config["scan_target_list"] = None

        self.config["safe_level"] = 4

        # make temp file for the KB save file
        self.kbSaveFile = self.config["proofsDir"] + "KB-" + Utils.getRandStr(10) + ".save"

        self.threadcount_thread = None

    # ==================================================
    # SUPPORT METHODS
    # ==================================================

    # ----------------------------
    # Setup Directories
    # ----------------------------
    def setupDirs(self):
        # make directories
        if not os.path.isdir(self.config["outDir"] + "reports/"):
            os.makedirs(self.config["outDir"] + "reports/")
        self.reportDir = self.config["outDir"] + "reports/"

        if not os.path.isdir(self.config["outDir"] + "logs/"):
            os.makedirs(self.config["outDir"] + "logs/")
        self.config["logDir"] = self.config["outDir"] + "logs/"
        self.display.setLogPath(self.config["logDir"])

        if not os.path.isdir(self.config["outDir"] + "proofs/"):
            os.makedirs(self.config["outDir"] + "proofs/")
        self.config["proofsDir"] = self.config["outDir"] + "proofs/"

        if not os.path.isdir(self.config["outDir"] + "tmp/"):
            os.makedirs(self.config["outDir"] + "tmp/")
        self.config["tmpDir"] = self.config["outDir"] + "tmp/"

        if not os.path.isdir(self.config["outDir"] + "misc/"):
            os.makedirs(self.config["outDir"] + "misc/")
        self.config["miscDir"] = self.config["outDir"] + "misc/"

    # ----------------------------
    # Check the current Version
    # ----------------------------
    def versionCheck(self):
        try:
            pattern = "'(\d+\.\d+\.\d+[^']*)'"
            # Get the VERSION that exists on Github
            # emote = re.search(pattern, self.request(
            # 'https://raw.githubusercontent.com/tatanus/automated_pentest/master/VERSION').raw).group(1)
            remote = re.search(pattern, open('VERSION_remote').read()).group(1)
            # Get the version that is local
            local = re.search(pattern, open('VERSION').read()).group(1)
            self.version = local
            if remote != local:
                self.display.alert('Your version of %s does not match the latest release.' % self.progName)
                self.display.alert('Please update or use the \'--no-check\' switch to continue using the old version.')
                if remote.split('.')[0] != local.split('.')[0]:
                    self.display.alert('Read the migration notes for pre-requisites before upgrading.')
                self.display.output('Remote version:  %s' % (remote))
                self.display.output('Local version:   %s' % (local))
                self.cleanup()
        except:
            self.cleanup()

    # ----------------------------
    # CTRL-C display and exit
    # ----------------------------
    def ctrlc(self):
        self.display.alert("Ctrl-C caught!!!")

        self.cleanup()

    # ----------------------------
    # Close everything down nicely
    # ----------------------------
    def cleanup(self):
        # kill thread count thread
        EventHandler.kill_thread_count_thread()

        # exit
        sys.exit(0)

    # ----------------------------
    # Display the Banner
    # ----------------------------
    def displayBanner(self):
        self.display.output()
        self.display.output("      dM.    `MMMMMMMb. MMMMMMMMMM      ")
        self.display.output("     ,MMb     MM    `Mb /   MM   \      ")
        self.display.output("     d'YM.    MM     MM     MM   ____   ")
        self.display.output("    ,P `Mb    MM     MM     MM  6MMMMb  ")
        self.display.output("    d'  YM.   MM    .M9     MM MM'  `Mb ")
        self.display.output("   ,P   `Mb   MMMMMMM9'     MM      ,MM ")
        self.display.output("   d'    YM.  MM            MM     ,MM' ")
        self.display.output("  ,MMMMMMMMb  MM            MM   ,M'    ")
        self.display.output("  d'      YM. MM            MM ,M'      ")
        self.display.output("_dM_     _dMM_MM_          _MM_MMMMMMMM ")
        self.display.output()

        self.display.output()
        self.display.output("An Automated Penetration Testing Toolkit")
        self.display.output("Written by: Adam Compton & Austin Lane")
        self.display.output("Verion: %s" % self.version)
        self.display.output()
        self.display.output("%i : Input Modules Loaded" % len(self.inputModules))
        self.display.output("%i : Action Modules Loaded" % len(self.actionModules))
        self.display.output()
        self.display.alert("The KnowledgeBase will be auto saved to : %s" % self.kbSaveFile)
        self.display.output()
        self.display.alert("Local IP is set to : %s" % self.config['lhost'])
        self.display.alert(
            "      If you would rather use a different IP, then specify it via the [--ip <ip>] argument.")

        # test to see if we can connect to msfrpc
        msf = myMsf(host=self.config['msfhost'], port=self.config['msfport'], user=self.config['msfuser'],
                    password=self.config['msfpass'])
        if (not msf.isAuthenticated()):
            self.display.output()
            self.display.error("Could not connect to Metasploit msgrpc service with the following parameters:")
            self.display.error("     host     = [%s]" % (self.config['msfhost']))
            self.display.error("     port     = [%s]" % (self.config['msfport']))
            self.display.error("     user     = [%s]" % (self.config['msfuser']))
            self.display.error("     password = [%s]" % (self.config['msfpass']))
            self.display.alert(
                "If you wish to make use of metasploit modules within Skiddy, please update the config file with the "
                "appropiate settings.")

        self.display.output()

    # ----------------------------
    # Parse CommandLine Parms
    # ----------------------------
    def parseParameters(self, argv):
        parser = argparse.ArgumentParser()

        # ==================================================
        # Input Files
        # ==================================================
        filesgroup = parser.add_argument_group('inputs')
        filesgroup.add_argument("-C",
                                metavar="<config.txt>",
                                dest="config_file",
                                action='store',
                                help="config file")
        filesgroup.add_argument("-f",
                                metavar="<input file>",
                                dest="inputs",
                                default=[],
                                action='store',
                                help="one of more input files seperated by spaces",
                                nargs='*')
        filesgroup.add_argument("--target",
                                metavar="",
                                dest="scan_target",
                                action='store',
                                help="initial scan target(s)")

        # ==================================================
        # Advanced Flags
        # ==================================================
        advgroup = parser.add_argument_group('ADVANCED')
        advgroup.add_argument("--ip",
                              metavar="<local IP>",
                              dest="lhost",
                              default=Utils.getIP(),
                              action='store',
                              help="defaults to %s" % Utils.getIP())

        # ==================================================
        # Optional Args
        # ==================================================
        parser.add_argument("-v", "--verbosity",
                            dest="verbose",
                            action='count',
                            help="increase output verbosity")
        parser.add_argument("-s", "--safelevel",
                            dest="safe_level",
                            action='store',
                            default=4,
                            help="set min safe level for modules")
        parser.add_argument("-b", "--bypassmenu",
                            dest="bypass_menu",
                            action='store_true',
                            help="bypass menu and run from command line arguments")
        # ==================================================
        # Misc Flags
        # ==================================================
        miscgroup = parser.add_argument_group('misc')
        miscgroup.add_argument("--listmodules",
                               dest="list_modules",
                               action='store_true',
                               help="list out all current modules")

        # parse args
        args = parser.parse_args()

        # convert parameters to values in the config dict
        self.config["config_filename"] = args.config_file
        self.config["verbose"] = args.verbose
        self.config["list_modules"] = args.list_modules
        self.config["scan_target"] = args.scan_target
        self.config["safe_level"] = int(args.safe_level)
        self.config['lhost'] = args.lhost
        self.config["bypass_menu"] = args.bypass_menu
        for f in args.inputs:
            type = self.idFileType(f)
            if (type):
                if type in self.inputs:
                    self.inputs[type].append(f)
                else:
                    self.inputs[type] = [f]

    # ----------------------------
    # Load config setting from the config file
    # ----------------------------
    def loadConfig(self):
        # does config file exist?
        if (("config_filename" in self.config) and (self.config["config_filename"] is not None)):
            temp1 = self.config
            temp2 = Utils.load_config(self.config["config_filename"])
            self.config = dict(temp2.items() + temp1.items())
        else:
            # guess not..   so try to load the default one
            if Utils.isReadable("default.cfg"):
                self.display.error("a CONFIG FILE was not specified...  defaulting to [default.cfg]")
                temp1 = self.config
                temp2 = Utils.loadConfig("default.cfg")
                self.config = dict(temp2.items() + temp1.items())
            else:
                # someone must have removed it!
                self.display.error("a CONFIG FILE was not specified...")
                self.cleanup()

        # set verbosity/debug level
        if ("verbose" in self.config):
            if (self.config['verbose'] >= 1):
                self.display.enableVerbose()
            if (self.config['verbose'] > 1):
                self.display.enableDebug()

    # ----------------------------
    # Load Initial Events
    # ----------------------------
    def populateInitEvents(self):
        EventHandler.fire("always:initial")

    # ----------------------------
    # look for and load and modules (input/action)
    # ----------------------------
    def loadModules(self):
        module_list = []

        # crawl the module directory and build the module tree
        # process inputs
        path = os.path.join(sys.path[0], 'modules/input')
        for dirpath, dirnames, filenames in os.walk(path):
            # remove hidden files and directories
            filenames = [f for f in filenames if not f[0] == '.']
            dirnames[:] = [d for d in dirnames if not d[0] == '.']
            if len(filenames) > 0:
                for filename in [f for f in filenames if (f.endswith('.py') and not f == "__init__.py")]:
                    module_list.append(self.loadModule("input", dirpath, filename))
        # process actions
        path = os.path.join(sys.path[0], 'modules/action')
        for dirpath, dirnames, filenames in os.walk(path):
            # remove hidden files and directories
            filenames = [f for f in filenames if not f[0] == '.']
            dirnames[:] = [d for d in dirnames if not d[0] == '.']
            if len(filenames) > 0:
                for filename in [f for f in filenames if (f.endswith('.py') and not f == "__init__.py")]:
                    module_list.append(self.loadModule("action", dirpath, filename))

        return module_list

    # ----------------------------
    # load each module
    # ----------------------------
    def loadModule(self, type, dirpath, filename):
        module_str = ""

        mod_name = filename.split('.')[0]
        mod_dispname = '/'.join(re.split('/modules/' + type + "/", dirpath)[-1].split('/') + [mod_name])
        mod_loadname = mod_dispname.replace('/', '_')
        mod_loadpath = os.path.join(dirpath, filename)
        mod_file = open(mod_loadpath)
        try:
            # import the module into memory
            imp.load_source(mod_loadname, mod_loadpath, mod_file)
            # find the module and make an instace of it
            _module = __import__(mod_loadname)
            _class = getattr(_module, mod_name)
            _instance = _class(self.config, self.display, self.modulelock)

            valid = True
            for r in _instance.getRequirements():
                if (not r in self.config):
                    path = Utils.validateExecutable(r)
                    if (path):
                        self.config[r] = path
                    else:
                        valid = False
            if (valid):
                module_str = "%s %s [TYPE = %s] [VALID = TRUE ]" % (
                    mod_name.ljust(25), _instance.getTitle().ljust(40), type.ljust(6))
            else:
                module_str = "%s %s [TYPE = %s] [VALID = FALSE]" % (
                    mod_name.ljust(25), _instance.getTitle().ljust(40), type.ljust(6))

            # add the module to the framework's loaded modules
            if (valid):
                if (type == "action"):
                    if (self.config["safe_level"] > _instance.getSafeLevel()):
                        self.display.error(
                            'Module \'%s\' disabled. Safety_level (%i) is below specified requirement (%i)' % (
                                mod_name, _instance.getSafeLevel(), self.config["safe_level"]))
                    else:
                        self.actionModules[mod_dispname] = _instance
                        for t in _instance.getTriggers():
                            EventHandler.add(_instance, t)
                elif (type == "input"):
                    self.inputModules[mod_dispname] = _instance
            else:
                self.display.error(
                    'Module \'%s\' disabled. Dependency required: \'%s\'' % (mod_name, _instance.getRequirements()))

        except ImportError as e:
            # notify the user of missing dependencies
            self.display.error('Module \'%s\' disabled. Dependency required: \'%s\'' % (mod_name, e))
        except Exception as e:
            # notify the user of errors
            print e
            self.display.error('Module \'%s\' disabled.' % (mod_name))

        return module_str

    # ----------------------------
    # Attempt to identify the type of input file
    # ----------------------------
    def idFileType(self, filename):
        # load and read first 4096 bytes of file
        file = open(filename, 'rb')
        data = file.read(4086)

        # get first line of of the 4096 bytes
        firstline = data.split('\n', 1)[0]

        # check firstline
        if (firstline.find("<NeXposeSimpleXML") != -1):
            return "nexpose_simple"
        elif (firstline.find("<NexposeReport") != -1):
            return "nexpose"
        elif (firstline.find("<NessusClientData>") != -1):
            return "nessus"
        elif (firstline.find("<?xml") != -1):
            # it's xml, check for root tags we can handle
            for line in data.split('\n'):
                parts = re.findall("<([a-zA-Z0-9\-\_]+)[ >]", line)
                for part in parts:
                    if part == "nmaprun":
                        return "nmap"

        return ""

    # ----------------------------
    # Main Menu
    # ---------------------------- 
    def displayMenu(self):
        if (self.config["bypass_menu"]):
            self.runScan()  # Skip first trip through menu and go straight into a scan using whatever arguments were
            # passed
            self.isRunning = False
            return
        self.display.output()
        self.display.output("---------------------------------------")
        self.display.output()
        self.display.output("1. Run")
        self.display.output("2. NMAP Settings")
        self.display.output("3. Browse KB")
        self.display.output("4. Quit")
        self.display.output()
        try:
            userChoice = int(self.display.input("Select an option: "))
            print "[" + str(userChoice) + "]"
            if (userChoice == 1):
                # Execute scan and begin process
                self.runScan()
            elif (userChoice == 2):
                # Configure NMAP Scan Settings
                self.displayNmapMenu()
            elif (userChoice == 3):
                # Browse data in the KB
                self.displayKbMenu()
            elif (userChoice == 4):
                # Quit
                self.isRunning = False
            else:
                self.display.error("%s - Not a valid option" % (userChoice))
        except ValueError:
            self.display.error("Not a valid option")

    # ----------------------------
    # Begin a Scan
    # ----------------------------
    def runScan(self):
        if (self.config["scan_target"]):
            nm = mynmap(self.config, self.display)
            nm.run(target=self.config["scan_target"], ports=self.config["scan_port_range"],
                   flags="-s" + self.config["scan_type"] + " " + self.config["scan_flags"], vector="nmapScan")
        elif (self.config["scan_target_list"]):
            nm = mynmap(self.config, self.display)
            nm.run(target="", ports=self.config["scan_port_range"],
                   flags="-s" + self.config["scan_type"] + " " + self.config["scan_flags"] + " -iL " + self.config[
                       "scan_target_list"], vector="nmapScan")
        # begin main loop
        while not EventHandler.finished():
            EventHandler.processNext(self.display, int(self.config['max_modulethreads']))
            # kb.save(self.kbSaveFile)

    # ----------------------------
    # Configure NMAP Scan Settings
    # ----------------------------
    def displayNmapMenu(self):
        while True:
            self.display.output()
            self.display.output("---------------------------------------")
            self.display.output()
            self.display.output("Current NMAP Settings: ")
            self.display.output("Scan Type: %s" % (self.config["scan_type"]))
            self.display.output("Flags: %s" % (self.config["scan_flags"]))
            self.display.output("Port Range: %s" % (self.config["scan_port_range"]))
            self.display.output("Target: %s" % (self.config["scan_target"]))
            self.display.output("Target List: %s" % (self.config["scan_target_list"]))
            self.display.output("Set: (s)can type, extra (f)lags, (p)ort range, (t)arget, target (l)ist, (m)ain menu")
            self.display.output()

            userChoice = self.display.input("Choose An Option: ")
            if userChoice == "s":
                self.config["scan_type"] = self.display.input("Choose S, T, U, ST, SU, TU: ")
            elif userChoice == "f":
                self.config["scan_flags"] = self.display.input("Set Extra Flags (ex: -A -Pn -T4): ")
            elif userChoice == "p":
                self.config["scan_port_range"] = self.display.input("Enter Range (1-65535): ")
            elif userChoice == "t":
                self.config["scan_target"] = self.display.input("Enter Target or Range (X.X.X.X/Y): ")
                self.config["scan_target_list"] = None
            elif userChoice == "l":
                filePath = self.display.input("Enter File Path (/tmp/targets.txt): ")
                if Utils.isReadable(filePath):
                    self.config["scan_target"] = None
                    self.config["scan_target_list"] = filePath
                else:
                    self.display.error("Unable to read file")
            elif userChoice == "m":
                break
            else:
                self.display.error("%s - Not a valid option" % (userChoice))

    # ----------------------------
    # Browse Knowledgebase
    # ----------------------------
    def displayKbMenu(self):
        searchString = ""
        depth = 0
        searches = {0: ""}
        self.display.output()
        self.display.output("---------------------------------------")
        self.display.output("Browse Knowledgebase")
        results = {}
        while True:
            self.display.output("[ " + searchString + " ]")
            if (searchString != ""):
                results = kb.get(searchString)
                i = 0
                for option in results:
                    self.display.output(str(i) + ". " + option)
                    i += 1
            else:
                self.display.output()
                self.display.output("0. host")
                self.display.output("1. service")
                self.display.output("2. domain")
                results = ["host", "service", "domain"]
                i = 3  # Keep selection filter from breaking
            self.display.output()
            self.display.output(
                "Choose From Above Or: (a)dd, (d)elete, (b)ack, (m)ain menu, (i)mport, write to (t)emp file")
            self.display.output()
            search = self.display.input("Select option or enter custom search path: ")
            if search == "m":
                break
            elif search == "b":
                if depth > 0:
                    depth -= 1
                searchString = searches[depth]
            elif search == "a":
                text = self.display.input("Input new record: ")
                kb.add(searchString + "/" + text.replace("/", "|"))
            elif search == "d":
                choice = self.display.input("Choose record to remove: ")
                try:
                    if int(choice) in range(i):
                        kb.rm(searchString + "/" + results[int(choice)])
                    else:
                        self.display.error("%s - Not a valid option" % (choice))
                except ValueError:
                    self.display.error("Not a valid option")
            elif search == "i":
                self.display.error("Not implemented yet")
            elif search == "t":
                tempPath = self.config["tmpDir"] + "KBRESULTS-" + Utils.getRandStr(10) + ".txt"
                text = ""
                for line in results:
                    text = text + line + "\n"
                Utils.writeFile(text, tempPath)
                self.display.output("Results written to: %s" % (tempPath))
            elif re.match("([a-zA-Z0-9.\*]*/)+([a-zA-Z0-9.\*]*)", search) != None:
                # Input in form of a/b/c/d, search keystore
                searchString = search
                depth = 0
                searches[depth] = searchString
            else:
                try:
                    if int(search) in range(i):
                        if searchString == "":
                            searchString = results[int(search)]
                        else:
                            searchString = searchString + "/" + results[int(search)]
                        depth += 1
                        searches[depth] = searchString
                    else:
                        self.display.error("%s - Not a valid option" % (search))
                except ValueError:
                    self.display.error("%s - Not a valid option" % (search))

    # ==========================================================================================
    # ==========================================================================================
    # ==========================================================================================

    # ----------------------------
    # Primary METHOD
    # ----------------------------
    def run(self, argv):
        # load config
        self.parseParameters(argv)
        self.loadConfig()

        # check the local version against the remote version
        self.versionCheck()

        # load input/action modules
        str = self.loadModules()

        # Everything must have loaded properly, so display the banner
        self.displayBanner()
        if (self.config["list_modules"]):
            self.display.print_list("List of Current Modules", str)
            self.display.output("")

        # parse inputs
        for input in self.inputs.keys():
            for inputmodule in self.inputModules.keys():
                _instance = self.inputModules[inputmodule]
                if (_instance.getType() == input):
                    for file in self.inputs[input]:
                        self.display.verbose("Loading [%s] with [%s]" % (file, inputmodule))
                        _instance.go(file)

        # populate any inital events
        self.populateInitEvents()

        # begin menu loop
        self.threadcount_thread = Thread(target=EventHandler.print_thread_count, args=(self.display,))
        self.threadcount_thread.start()
        while self.isRunning:
            self.displayMenu()

        kb.save(self.kbSaveFile)

        self.display.output()
        self.display.output("Good Bye!")
        self.cleanup()
