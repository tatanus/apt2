from core.events import EventHandler


class inputModule(object):
    def __init__(self, config, display, lock):
        self.display = display
        self.config = config
        self.title = ""
        self.requirements = []
        self.description = ""
        self.type = ""
        self.lock = lock

    def getType(self):
        return self.type

    def getTitle(self):
        return self.title

    def getDescription(self):
        return self.description

    def getRequirements(self):
        return self.requirements

    def process(self):
        return

    def go(self, inputfile):
        self.display.verbose("-> Running : " + self.getTitle())
        return self.process(inputfile)

    def fire(self, trigger):
        EventHandler.fire(trigger + ":INPUTFile")

