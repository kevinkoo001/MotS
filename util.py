__author__ = 'Hyungjoon Koo (hykoo@cs.stonybrook.edu)'

import sys
import os
import netifaces
import logging
from datetime import *

# Check if provided interface is appropriate
def ifce_sanity_check(iface):
    if iface not in [x for x in netifaces.interfaces()]:
        print '[Error] Wrong network interface: %s' % iface
        sys.exit(1)
    return iface

# Return the default interface based on the gateway
def get_default_iface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

# Check the provided file from command line
def data_sanity_check(file):
    if not os.path.isfile(file):
        logging.warning('Inappropriate file provided!')
        sys.exit(1)
    return open(file, 'r').read()
    
def print_injection_info(i, p, d, b, f):
    print datetime.today().strftime("\t%B %d %Y %I:%M%p (%A)")
    print '\tPacket injection at <%s> interface' % i
    print '\t\tMonitoring with BPF: <%s>' % f
    print '\t\tFinding the pattern with regex: <%s>' %p
    print '\t\tInjecting data file: <%s> (%dB payload)' % (d, b)