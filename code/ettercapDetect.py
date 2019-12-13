from scapy.all import Ether, ARP, srp, sniff, conf

def get_mac(ip):
  #Returns true mac address of ip
  #Throws IndexError if blocked
  p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
  result = srp(p, timeout=3, verbose=False)[0]
  return result[0][1].hwsrc  

def test(pkt):
  #Filters for ARP responses only
  if not pkt.haslayer(ARP) or not pkt[ARP].op == 2:
    return
  try:
    #calls helper function for finding mac
    real_mac = get_mac(pkt[ARP].psrc)
    #gets mac address from packet
    response_mac = pkt[ARP].hwsrc

    #if they don't match, arp 
    #cache poisoning is occuring
    if real_mac != response_mac:
      print('ARP Cache Spoof Detected')
      print('Real mac addr: ', str(real_mac.upper()))
      print('Fake mac addr: ', str(response_mac.upper()))
      return

  except IndexError:
    pass
    

sniff(iface='Ethernet 10', prn=test, filter='arp', store=False)





