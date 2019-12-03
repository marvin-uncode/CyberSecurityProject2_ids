import pyshark
capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously():
  if packet.arp.duplicate-address-frame:
    print("ARP CACHE POISONING DETECTED")
    print("Attacker Machine:", str(packet.ip.src))
capture.sniff()
