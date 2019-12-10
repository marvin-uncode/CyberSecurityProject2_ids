import pyshark
from collections import defaultdict
capture = pyshark.LiveCapture(interface='eth0')

ack_ports = defaultdict(set()) #src port -> dst port 

for packet in capture.sniff_continuously():
  if tcp && tcp.flags.fin == 1 
    && (tcp.window_size==1024 || 
        tcp.window_size==2048 || 
        tcp.window_size==3072 || 
        tcp.window_size==4096):
    print("NMAP SYN SCAN DETECTED")
    print("Attacker Machine:", str(packet.ip.src))


  elif tcp && tcp.flags==0x29 && tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1:
    print('NMAP XMAS SCAN DETECTED')
    print("Attacker Machine:", str(packet.ip.src))
  
  elif tcp && tcp.flags==0x10 && tcp.flags.ack==1:
    ack_ports[tcp.srcport].add(tcp.dstport)
    if len(ack_ports[tcp.srcport]) > 15:
      print('NMAP ACK SCAN DETECTED')
      print("Attacker Machine:", str(packet.ip.src))
   
capture.sniff()
