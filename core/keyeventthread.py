from threading import Thread
import sys
import select

# ----------------------------
# KeyEventThread CLASS
# ----------------------------
class KeyEventThread(Thread):
    def __init__(self, pDisplay):
        Thread.__init__(self)
        self.end = False
        self.paused = False
        self.display = pDisplay

    def run(self):
        self.display.alert("Use the following controls while scans are running:")
        self.display.alert("- p - pause/resume event queueing")
        #detect key presses
        while not self.end:
            #run until end is True
            # TODO - This is Linux only, need to find fallback for windows, maybe msvctl.getch
            i, o, e = select.select( [sys.stdin], [], [], 1 )
            if i:
                ch = sys.stdin.read(1)
                if ch == 'p':
                    if self.paused:
                        self.display.alert("Queue is unpaused, progress will resume")
                        self.paused = False
                    else:
                        self.display.alert("Queue is paused, new events will not be loaded but current threads will continue")
                        self.paused = True

    def stop(self):
        self.end = True

    def isPaused(self):
        return self.paused