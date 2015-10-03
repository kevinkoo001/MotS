__author__ = 'Hyungjoon Koo (hykoo@cs.stonybrook.edu)'

import optparse
import os
import sys
import logging
from collections import deque
from datetime import *
import util

try:
    import netifaces
    from scapy.all import *
except ImportError:
    print 'Failed to import necessary packages'

VER = 0.1
PKT_INSPECTED_CNT = 200
MAX_COMPARISON = 100

class DetectorError:
    pass
    
class Detector:
    def __init__(self, type, iface, pcap, bpf):
        self.type = type
        self.iface = iface
        self.pcap = pcap
        self.bpf = bpf
        self.detected_cnt = 0
        
        # Assume the injection can be discovered within the recent MAX_COMPARISON packets
        self.pkt_queue = deque(maxlen = MAX_COMPARISON)
    
    def get_detected_pkt_cnt(self):
        return self.detected_cnt
        
    def pkt_investigation(self, pkt):
        # Investigate the identical flow (IP src/dst, TCP src/dst, seq and ack) but different payload
        def is_duplicate(x, y):
            return x[IP].src == y[IP].src and x[IP].dst == y[IP].dst and\
                   x[TCP].sport == y[TCP].sport and x[TCP].dport == y[TCP].dport and\
                   x[TCP].seq == y[TCP].seq and x[TCP].ack == y[TCP].ack and\
                   len(x[TCP]) > 32 and len(y[TCP]) > 32 and\
                   x[TCP].payload != y[TCP].payload
         
        # Check if any packet turns out to be duplicate in recent 100 packets
        if len(self.pkt_queue) > 0:
            for cmp_pkt in self.pkt_queue:
                if is_duplicate(cmp_pkt, pkt):
                    logging.warning('Detected suspicious (duplicated) packet (MotS?) [%d VS %d]' % (cmp_pkt[IP].id, pkt[IP].id))
                    self.detected_cnt += 1
        
        self.pkt_queue.append(pkt)
                    
    def sniff_n_detect(self, cnt = 100):
        try:
            if self.type == 'online':
                logging.info("[Online] Sniffing on %s" % self.iface)
                sniff(iface = self.iface, prn = lambda x: dt.pkt_investigation(x), filter = self.bpf, lfilter=lambda x:x.haslayer(TCP))
            elif self.type == 'offline':
                logging.info("[Offline] Sniffing at %s" % self.pcap)
                sniff(offline = self.pcap, prn = lambda x: dt.pkt_investigation(x), filter = self.bpf, lfilter=lambda x:x.haslayer(TCP))
            else:
                print 'Not supported type!'
                sys.exit(1)
        
        except DetectorError:
            logging.error("Something went wrong while detecting injected packets...!")
            sys.exit(1)

if __name__ == '__main__':
    usage  = "Usage: %prog -i <interface> -r <file> -b <bpf> (Use -h for help)"
    usage += "\n   [Offiline] %prog -r sample.pcap"
    usage += "\n   [Online]: %prog -i eth0 -b tcp"
    version = "%prog " + str(VER)
    
    p = optparse.OptionParser(usage=usage, version=version)
    
    p.add_option("-i", "--interface", dest="iface", action="store_true", 
                  help="interface of network device to listen on")

    p.add_option("-r", "--pcap", dest="pcap", action="store_true", 
                  help="captured file to be inspected for MotS")
                      
    p.add_option("-b", "--filter", dest="bpf", action="store_true", 
                      help="BPF filter that specifies a subset of the traffic to be monitored")
    
    print "quantumdetect %s" % VER
    (options, args) = p.parse_args()
    
    # Accept only when either offline or online mode respectively
    if len(args) != 2:
        logging.error('Double-check your arguments...!')
        sys.exit(1)

    logging.basicConfig(filename='detection.log', level=logging.DEBUG)
    logging.info('[Start] %s' % datetime.today().strftime("%B %d %Y %I:%M%p (%A)"))
    filter = args[1]

    # Proceed detection at online or offline
    if options.pcap and options.bpf:
        pcap_file = args[0]
        if not os.path.isfile(pcap_file):
            logging.warning('Inappropriate file provided!')
            sys.exit(1)
        dt = Detector('offline', iface=None, pcap=pcap_file, bpf=filter)
        dt.sniff_n_detect(PKT_INSPECTED_CNT)
        
    elif options.iface and options.bpf:
        dt = Detector('online', iface=util.ifce_sanity_check(args[0]), pcap=None, bpf=filter)
        dt.sniff_n_detect(PKT_INSPECTED_CNT)
        
    else:
        logging.error('Unsupported mode - How did you do that?')
        sys.exit(1)
    
    print '\t%d packets are detected as injection! (%d inspected)' % (dt.get_detected_pkt_cnt(), PKT_INSPECTED_CNT)
    logging.info('[End] %s' % datetime.today().strftime("%B %d %Y %I:%M%p (%A)"))
    