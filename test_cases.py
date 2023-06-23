#!/usr/bin/python3

import os
import sys
import time
import math

# Run the test for 4 times
for i in range(4):
    print("Test case {}".format(i+1))

    # Running the script to send traffic
    # The script randomly chooses two different hosts in different pods, and run send traffic in a flowlet manner
    # The flowlet gap is around 0.5sec
    # The script also uses TCPDUMP to record the traffic for the 4 links from the two aggregated switches to the four core switches
    # The two aggregated switches could be in either pod for the two hosts
    os.system("sudo bash tests/iperf_flowlet.sh")

    # Get the number of packets for the 4 links
    files = os.listdir("tcpdump_logs")
    d = []
    for file in files:
        with open("tcpdump_logs/"+ file, "r") as f:
            contents = f.read()
            d.append(len(contents))

    print("# of packets on the four links", d)
    
    # If the flowlet switching works, the deviation of the 4 numbers should be small
    avg = 0.0
    for item in d:
        avg += item
    avg /= len(d)
    dev = 0.0
    for item in d:
        dev += (item - avg) ** 2
    dev /= len(d)
    dev = math.sqrt(dev)
    dev = dev / avg
    print("stddev of four links", dev)

    if abs(dev) > 0.3:
        print("Test fail")
        exit()

print("Test pass")
