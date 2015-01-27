#!/usr/bin/env python

# This code will send a SYN packet to a remote host (rhost) in search of a SYN-ACK.
# If we get a SYN-ACK, we know the port (rport) is open.

from scapy.all import *
 
def main(rhost, rport):

    source_port = RandShort()

    try:
        rport=int(rport)

    except ValueError:
        print("{} does not appear to be a valid number.".format(rport))
        print("Please change the destination port value and try again.")
        return
 
    stealth_scan_resp = sr1(IP(dst=rhost)/TCP(sport=source_port,dport=rport,flags="S"),timeout=10)

    # If we don't recognize the response...
    if str(type(stealth_scan_resp))=="<type 'NoneType'>":
        print ("Port {} is Filtered or Closed (Packet silently dropped)".format(str(rport)))

    elif stealth_scan_resp.haslayer(TCP):
        # If the TCP packet flag is SYN-ACK, send RST-ACK
        # Note 0x12 or 18 decimal is SYN-ACK; there is currently no way to check "SA"
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=rhost)/TCP(sport=source_port,dport=rport,flags="RA"),timeout=10)
        print ("Port {} is Open".format(str(rport)))

    # If the TCP packet flag is ACK-RST, the port is closed.
    # Note 0x14 or 20 decimal is ACK_RST; there is currently no way to check "RA"
    elif stealth_scan_resp.getlayer(TCP).flags == 0x14:
        print ("Port {} is Closed".format(str(rport)))

    # See RFC 792 for ICMP Types and Codes
    # Additional detail at http://www.nthelp.com/icmp.html
    elif stealth_scan_resp.haslayer(ICMP):
        if int(stealth_scan_resp.getlayer(ICMP).type == 3 and int(
                 stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("Port {} is Filtered".format(str(rport)))

if __name__ == "__main__":
    remote_ip = raw_input("What is the remote IP ? ")
    remote_port = raw_input("What is the remote port? ")
    main(remote_ip, remote_port)