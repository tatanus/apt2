from multiprocessing.pool import ThreadPool
from scapy.all import *


class pktcap():
    def capture(self, filter="", timeout=60, count=1, srcip="", dstip=""):
        results = "Packet Capture  of (%s -> %s) filter (%s)\n\n" % (srcip, dstip, filter)
        pkts = sniff(filter=filter, timeout=timeout, count=count)
        for pkt in pkts:
            ip_src = ""
            ip_dst = ""
            tcp_sport = 0
            tcp_dport = 0
            tcp_payload = ""
            if IP in pkt:
                ip_src = str(pkt[IP].src)
                ip_dst = str(pkt[IP].dst)
            if TCP in pkt:
                tcp_sport = int(pkt[TCP].sport)
                tcp_dport = int(pkt[TCP].dport)
                tcp_payload = str(pkt[TCP].payload)

            if (tcp_payload.strip() == ""):
                continue

            if (srcip == "") and (dstip == ""):
                results += ">><< %s\n" % (tcp_payload)
            elif (srcip == ""):
                if (ip_dst == dstip):
                    results += ">>>> %s\n" % (tcp_payload)
                else:
                    results += "<<<< %s\n" % (tcp_payload)
            else:
                if (ip_src == srcip):
                    results += ">>>> %s\n" % (tcp_payload)
                else:
                    results += "<<<< %s\n" % (tcp_payload)

        return results


# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    filter = "(host 192.168.1.8 or host 192.168.124) and tcp and port 21"
    pktcount = 20
    pkttimeout = 50
    srcip = "192.168.1.124"
    dstip = "192.168.1.8"

    pool = ThreadPool(processes=1)

    p = pktcap()

    #    print p.capture(filter=filter, timeout=pkttimeout, count=pktcount, srcip=srcip, dstip=dstip)
    # tuple of args for foo, please note a "," at the end of the arguments
    async_result = pool.apply_async(p.capture, (filter, pkttimeout, pktcount, srcip, dstip,))

    # Do some other stuff in the main process
    print "hi"

    print async_result.get()
