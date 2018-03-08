import Queue
import time
from threading import Thread


class ActiveThreadListItem():
    def __init__(self, thread, name):
        self.thread = thread
        self.name = name

    def getThread(self):
        return self.thread

    def getName(self):
        return self.name


class EventObject():
    def __init__(self, _instance, vector, event):
        self._instance = _instance
        self.vector = vector
        self.event = event

    def get_event(self):
        return self.event

    def get_name(self):
        return self._instance.getShortName()

    def get_instance(self):
        return self._instance

    def get_vector(self):
        return self.vector


class EventQueue():
    eventQueue = Queue.Queue()

    @staticmethod
    def pop():
        return EventQueue.eventQueue.get()

    @staticmethod
    def push(evtobj):
        print("NEW EVENT: " + evtobj.get_event())
        EventQueue.eventQueue.put(evtobj)
        return

    @staticmethod
    def empty():
        return EventQueue.eventQueue.empty()

    @staticmethod
    def size():
        return EventQueue.eventQueue.qsize()


class EventHandler(object):
    eventList = {}
    nameList = list()
    my_threads = list()
    ActiveThreadCountThread = False

    @staticmethod
    def add(_instance, event):
        if (event in EventHandler.eventList):
            EventHandler.eventList[event].append(_instance)
        else:
            EventHandler.eventList[event] = [_instance]

    @staticmethod
    def remove(_instance, event):
        if (event in EventHandler.eventList):
            EventHandler.eventList[event].remove(_instance)

    @staticmethod
    def fire(event):
        parts = event.split(":")
        event = parts[0]
        vector = ""
        if (len(parts) == 2):
            vector = parts[1]

        # make sure this event/vector pair is not already in the queue
        if not (event + ":" + vector) in EventHandler.nameList:
            if (event in EventHandler.eventList):
                for _instance in EventHandler.eventList[event]:
                    EventQueue.push(EventObject(_instance, vector, event))
                    EventHandler.nameList.append(event + ":" + vector)

    @staticmethod
    def numActiveThreads(name):
        num = 0
        for t in EventHandler.my_threads:
            if t.getName() == name:
                num = num + 1
        return num

    @staticmethod
    def colapsethreads():
        tmp_threads = list()
        for t in EventHandler.my_threads:
            if t.getThread().isAlive():
                tmp_threads.append(t)
        EventHandler.my_threads = tmp_threads

    @staticmethod
    def finished():
        EventHandler.colapsethreads()
        if (EventQueue.empty() and (len(EventHandler.my_threads) == 0)):
            return True
        return False

    @staticmethod
    def kill_thread_count_thread():
        EventHandler.ActiveThreadCountThread = False

    @staticmethod
    def print_thread_count(display, delay=5):
        EventHandler.ActiveThreadCountThread = True
        while (EventHandler.ActiveThreadCountThread):
            while (EventHandler.ActiveThreadCountThread and len(EventHandler.my_threads) == 0):
                time.sleep(delay)
            display.alert("Current # of Active Threads = [%i]" %
                    len(EventHandler.my_threads))
            tmp_list = ""
            for t in EventHandler.my_threads:
                if not tmp_list == "":
                    tmp_list = tmp_list + ", "
                tmp_list = tmp_list + t.getName()
            display.alert("    ==> " + tmp_list)
            display.debug("EventQueue Size = [%i]" % EventQueue.size())
            time.sleep(delay)

    @staticmethod
    def processNext(display, max_threads):

        # wait for a thread to free up
        while (len(EventHandler.my_threads) >= max_threads):
            EventHandler.colapsethreads()

        # make sure there are events to process
        if not EventQueue.empty():
            evtobj = EventQueue.pop()
            _instance = evtobj.get_instance()
            vector = evtobj.get_vector()
            event = evtobj.get_event()

            EventHandler.nameList.remove(event + ":" + vector)

            # check to see if the target module is at maxThreads and if so, add it back to the queue

            if _instance and (
                        EventHandler.numActiveThreads(_instance.getShortName()) >= int(_instance.getMaxThreads())):
                EventHandler.fire(event + ":" + vector)
            else:
                display.verbose("Launching [%s] Vector [%s]" % (_instance.getTitle(), vector))
                if _instance:
                    thread = Thread(target=_instance.go, args=(vector,))
                    thread.setDaemon(True)
                    thread.start()
                    EventHandler.my_threads.append(ActiveThreadListItem(thread, _instance.getShortName()))
                    # _instance.go(vector)
