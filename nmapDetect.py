import pyshark
from collections import defaultdict
capture = pyshark.LiveCapture(interface='eth0')

ack_ports = defaultdict(set()) #src port -> dst port 

for packet in capture.sniff_continuously():
  if packet.tcp && packet.tcp.flags.fin == 1 
    && (packet.tcp.window_size==1024 || 
        packet.tcp.window_size==2048 || 
        packet.tcp.window_size==3072 || 
        packet.tcp.window_size==4096):
    print("NMAP SYN SCAN DETECTED")
    print("Attacker Machine:", str(packet.ip.src))


  elif packet.tcp && packet.tcp.flags==0x29 && packet.tcp.flags.fin==1 && packet.tcp.flags.push==1 && packet.tcp.flags.urg==1:
    print('NMAP XMAS SCAN DETECTED')
    print("Attacker Machine:", str(packet.ip.src))
  
  elif packet.tcp && packet.tcp.flags==0x10 && packet.tcp.flags.ack==1:
    ack_ports[packet.tcp.srcport].add(packet.tcp.dstport)
    if len(ack_ports[packet.tcp.srcport]) > 15:
      print('NMAP ACK SCAN DETECTED')
      print("Attacker Machine:", str(packet.ip.src))
   
capture.sniff()
