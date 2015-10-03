# MotS
Man on the Side Attack - experimental packet injection and detection

A. Required packages 
    netifaces
    scapy
    $ pip install netifaces scapy
    
B. Source code (written in python)
    quantuminject.py    ... Mots Injector
    quantumdetect.py    ... MotS detector
    util.py             ... Common functions
    README.md           ... This file
    test.dat            ... Contents to be injected as TCP payload
    
C. Usage

    # python quantumdetect.py -h
        quantumdetect 0.1
        Usage: quantumdetect.py -i <interface> -r <file> -b <bpf> (Use -h for help)
           [Offiline] quantumdetect.py -r sample.pcap
           [Online]: quantumdetect.py -i eth0 -b tcp
        Options:
          --version        show program's version number and exit
          -h, --help       show this help message and exit
          -i, --interface  interface of network device to listen on
          -r, --pcap       captured file to be inspected for MotS
          -b, --filter     BPF filter that specifies a subset of the traffic to be monitored
      
    # python quantuminject.py -h
        quantuminject 0.3
        Usage: quantuminject.py -i <interface> -r <regex> -d <data> -b <bpf> (Use -h for help)
           eg: quantuminject.py -i eth0 -r 'w?rks' -d sample.txt -b tcp
        Options:
          --version        show program's version number and exit
          -h, --help       show this help message and exit
          -i, --interface  interface of network device to listen on
          -r, --regex      regular expression to match the request packets for being spoofed
          -d, --datafile   raw data to be used as TCP payload of the spoofed response
          -b, --filter     BPF filter that specifies a subset of the traffic to be monitored

D. Tested example 
    a. All logs are recorded as a file. [injection.log or detection.log]
    b. Note that the numbers in logs are IP IDs to be able to keep track of.
    c. 'quantumdetect.py' can be either online or offline mode depending on provided arguments
    
    # python quantuminject.py -i eth0 -r 'nop..nlife' -d ./test.dat -b 'dst xxx.xxx.xxx.xxx'
        quantuminject 0.3
            October 03 2015 12:52AM (Saturday)
            Packet injection at <eth0> interface
                    Monitoring with BPF: <dst xxx.xxx.xxx.xxx.xxx>
                    Finding the pattern with regex: <nop..nlife>
                    Injecting data file: <./test.dat> (404B payload)
                    (1) Injected packet IP ID: 22587 (corresponding 63411)
                    (2) Injected packet IP ID: 9246 (corresponding 26689)
            2 packets are injected! (20 monitored)
    # tail -7 injection.log
        INFO:root:[Start] October 03 2015 12:52AM (Saturday)
        INFO:root:Sniffing on eth0
        WARNING:root:Pattern (nop..nlife) found in the packet IPID: 63411
        WARNING:root:Injected the forged packet successfully! (MotS)
        WARNING:root:Pattern (nop..nlife) found in the packet IPID: 26689
        WARNING:root:Injected the forged packet successfully! (MotS)
        INFO:root:[End] October 03 2015 12:53AM (Saturday)
    # python quantumdetect.py -r ./test.pcap -b 'dst xxx.xxx.xxx.xxx'  (offline mode)
        quantumdetect 0.1
            5 packets are detected as injection! (200 inspected)
    # tail -8 detection.log
        INFO:root:[Start] October 03 2015 12:31AM (Saturday)
        INFO:root:[Offline] Sniffing at ./noplanlife.pcap
        WARNING:root:Detected suspicious (duplicated) packet (MotS?) [18931 VS 1348]
        WARNING:root:Detected suspicious (duplicated) packet (MotS?) [48881 VS 1377]
        WARNING:root:Detected suspicious (duplicated) packet (MotS?) [48881 VS 1383]
        WARNING:root:Detected suspicious (duplicated) packet (MotS?) [48881 VS 1395]
        WARNING:root:Detected suspicious (duplicated) packet (MotS?) [1391 VS 1412]
        INFO:root:[End] October 03 2015 12:31AM (Saturday)
    # python quantumdetect.py -i eth0 -b 'dst xxx.xxx.xxx.xxx' (online mode)
        quantumdetect 0.1
            5 packets are detected as injection! (200 inspected)
