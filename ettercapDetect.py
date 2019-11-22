import pyshark
capture = pyshark.LiveCapture(interface='eth0', display_filter='arp.duplicate-address-frame')
for packet in capture.sniff_continuously():
    print("ARP CACHE POISONING DETECTED")
    print("Attacker Machine:", str(packet.ip.src))
capture.sniff()
