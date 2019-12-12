import pyshark
from collections import defaultdict
capture = pyshark.LiveCapture(interface='eth0')

ack_ports = defaultdict(set()) #src port -> dst port (ack scan)
syn_ports = defaultdict(set()) #src port -> dst port (syn scan)

for packet in capture.sniff_continuously():
  if packet.tcp and packet.tcp.flags == 0x02 
    and (packet.tcp.window_size==1024 or 
        packet.tcp.window_size==2048 or 
        packet.tcp.window_size==3072 or 
        packet.tcp.window_size==4096):

    syn_ports[packet.tcp.srcport].add(packet.tcp.dstport)
    if len(syn_ports[packet.tcp.srcport]) > 15:
      print("NMAP SYN SCAN DETECTED")
      print("Attacker Machine:", str(packet.ip.src))


  elif packet.tcp and packet.tcp.flags==0x29:
    print('NMAP XMAS SCAN DETECTED')
    print("Attacker Machine:", str(packet.ip.src))
  
  elif packet.tcp and packet.tcp.flags==0x10:
    ack_ports[packet.tcp.srcport].add(packet.tcp.dstport)
    if len(ack_ports[packet.tcp.srcport]) > 15:
      print('NMAP ACK SCAN DETECTED')
      print("Attacker Machine:", str(packet.ip.src))
   
capture.sniff()
