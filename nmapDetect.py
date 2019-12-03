import pyshark
capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously():
  if tcp && tcp.flags.fin == 1 
    && (tcp.window_size==1024 || 
        tcp.window_size==2048 || 
        tcp.window_size==3072 || 
        tcp.window_size==4096):
    print("NMAP SYN SCAN DETECTED")
    print("Attacker Machine:", str(packet.ip.src))


  if tcp && tcp.flags==0x29 && tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1:
    print('NMAP XMAS SCAN DETECTED')
    print("Attacker Machine:", str(packet.ip.src))
capture.sniff()
