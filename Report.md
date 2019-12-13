\title{COMP 5970/6970: HTTP Reverse Shell}
\author{Alex Lewin, Charlie Harper}
\date{11/8/19}

---
geometry:
- margin=1.5in
...

\maketitle

# 1 Executive Summary 

The purpose of this project was to develop and demonstrate our understanding of the basics of Intrusion Detection Programs (IDS), the different types of IDS, and the process of creating a proprietary IDS.  
 
Our assignment was to pose as member of a company's *"blue team"*, protecting our company against malware. To do this, we designed and tested a proprietary IDS that detects a variety of attacks.  

**Our script, that utilizes *signature* and *heuristic* based itrusion detection, does successfully detects a variety of attacks.**


\newpage
# 2 Problem Description

## 2.1 Problem Overview  

Our assignment was to pose as member of a company's *"blue team"*, protecting our company against malware. To do this, we were instructed to design and test a proprietary IDS that detects utilizes at least **two of the following four types of network IDS**. 

   * **Behavioral**  
   * **Anomaly**  
   * **Signature**  
   * **Heuristic**  

Our script must detect the following attack tools being run againsts the network:  

   * **NMAP - SYN, ACK, and Christmas Scans**  
   * **Ettercap**  
   * **Responder**  
   * **Metasploit - CVE-2017-010 - ms17_010_psexec**  

## 2.2 Technical Specifications

##### Attacker machine specifications:

   - Operating System: **Kali Linux**  
   - Server Location: **Shelby 2129**  
   - IP Address: **192.168.x.10**  
   

##### Detection machine specifications:  

   - Operating System: **Microsoft Windows 10**
   - Server Location: **Shelby 2129**  
   - IP Address: **192.168.x.30**  
   - `python3 --version`: **`Python 3.6.7`**  

\newpage
# 3 Information Discovery

In order to create a program that detects specific attacks, we conducted some exploritory tests. For each script, we ran the attack with wireshark in the backround so we could analyze the unique aspects of the attack with the goal of reverse engineering a detection scheme.

## 3.1 NMAP

To learn how to detect NMAP scans on the network, we first ran the different types of scans with Wireshark performing packet capture in the backround. While we approached the detection of each NMAP scan with the same strategy, we had to use slightly different checks for each scan.  

### 3.1.1 SYN Scan

Because of the frequency of legitmate TCP SYN packets, we had to find a distinguishing factor of NMAP SYN scan packets. From online research, we discovered that NMAP SYN scan packets always have a standard window size: 1024, 2048, 3072, or 4096.

From the information about the window size and given that NMAP SYN scan packets have the FIN flag set, we can distinguish a SYN scan packet using the following Wireshark flags:  

   `tcp and tcp.flags == 0x02 and (tcp.window_size==1024 or tcp.window_size==2048 or tcp.window_size==3072 or tcp.window_size==4096)`  

In addition, we utilized a *heuristic* solution to detect NMAP SYN scan traffic. Knowing that an SYN scan generally sends packets to a large number of destination ports, we can detect an SYN scan by keeping track of the source and destination ports of the packets.   


![Initial SYN Scan][syntest]\  


### 3.1.2 ACK Scan

Because of the frequency of legitimate TCP ACK packets, we utilized a *heuristic* solution to detect NMAP ACK scan traffic. Knowing that an ACK scan generally sends packets to a large number of destination ports, we can detect an ACK scan by keeping track of the source and destination ports of the packets. We use this Wireshark filter to detect ACK packets:  
   `tcp and tcp.flags==0x10`    


![Initial ACK Scan][acktest]\  


### 3.1.3 XMAS Scan

Because XMAS scans utilize several TCP flags in an otherwise uncommon combination, we can detect XMAS scan packets by simply checking the size of the TCP flags and which flags are currently set (FIN, PSH, URG): 
   `tcp and tcp.flags==0x29`  

![Initial XMAS Scan][xmastest]\


## 3.2 Ettercap

To learn how to detect a man-in-the-middle attack from Ettercap, we first ran the attack on our network while monitoring the traffic using Wireshark. Since PyShark does not have any support for ARP traffic, we decided to use the python module *Scapy* instead. To detect if an ARP Cache Spoof has occured, we checked if the reported source mac address in each packet, matched the true mac address.  

## 3.3 Responder

![Initial Responder Test][respondertest]\  


## 3.4 Metasploit - CVE-2017-010 - ms17_010_psexec

\newpage
# 4 Code Explanation

## 4.1 NMAP Detection  

```python

#To detect an ACK and SYN Scan, we store a set of witnessed 
# destination ports for each source port. 
ack_ports = defaultdict(set()) #src port -> dst port (ack scan)
syn_ports = defaultdict(set()) #src port -> dst port (syn scan)

#Performing a live capture over eth0 
capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously():
  
  #Check for SYN Scan as described in section 3.1.1
  if packet.tcp and packet.tcp.flags.fin == 1 
      and (packet.tcp.window_size==1024 or packet.tcp.window_size==2048 or 
          packet.tcp.window_size==3072 or packet.tcp.window_size==4096):
    
    #Maps seen destination ports to each source port.
    # Key: source port ==> Value: set of destination ports from this source
    syn_ports[packet.tcp.srcport].add(packet.tcp.dstport)


    #Trigger detection if more than 15 destination ports 
    # are sent from the same source port. 
    if len(syn_ports[packet.tcp.srcport]) > 15:

      #Print source ip
      print("NMAP SYN SCAN DETECTED")
      print("Attacker Machine:", str(packet.ip.src))

    
  #Check for XMAS Scan as described in section 3.1.3
  elif packet.tcp and packet.tcp.flags==0x2:
    print('NMAP XMAS SCAN DETECTED')

    #Print source ip
    print("Attacker Machine:", str(packet.ip.src))


  #For ACK Scan, we only need to analyze ACK packets 
  elif packet.tcp and packet.tcp.flags==0x10:

    #Maps seen destination ports to each source port.
    # Key: source port ==> Value: set of destination ports from this source
    ack_ports[packet.tcp.srcport].add(packet.tcp.dstport)

    #Trigger detection if more than 15 destination ports 
    # are sent from the same source port. 
    if len(ack_ports[packet.tcp.srcport]) > 15:
      print('NMAP ACK SCAN DETECTED')
      print("Attacker Machine:", str(packet.ip.src))


```

## 4.2 Ettercap Detection

Ettercap is a piece of software that can facilitate **Man-in-the-Middle** attacks. In order to accomplish this, Ettercap first performs **ARP Cache Poisoning** which is what we decided to detect.  

Since Wireshark does not implement a way to directly filter for ARP traffic, we opted to use the python module, **scapy**, instead.


```python

from scapy.all import Ether, ARP, srp, sniff, conf

#Helper function to find mac addr
def get_mac(ip):
  #Returns true mac address of ip
  #Throws IndexError if blocked
  p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
  result = srp(p, timeout=3, verbose=False)[0]
  return result[0][1].hwsrc  

def checker(pkt):
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
    print('indexerror')
    pass
    
#Passes every sniffed packed to 'checker'
sniff(iface='Ethernet 10', prn=checker, filter='arp', store=False)

```

## 4.3 Responder Detection

## 4.4 Metasploit Detection


\newpage
# 5 Testing and Packet Capture  

For each attack, we deployed Wireshark and our intrusion detection system in the background.  

## 5.1 NMAP Detection  

### 5.1.1 SYN Scan

![SYN Scan Detection][syngood]\

### 5.1.2 ACK Scan

![ACK Scan Detection][ackgood]\


### 5.1.3 XMAS Scan

![XMAS Scan Detection][xmasgood]\

## 5.2 Ettercap Detection

![Ettercap Test][ettercapfound]\
![Ettercap Result][ettercapcmd]\

## 5.3 Responder Detection

## 5.4 Metasploit Detection


\newpage
# 6 Conclusions

In completing this assignment, we were successfully able to deploy and detect each of the four attacks using a proprietary intrusion detection system, all while monitoring and analyzing the network traffic. After completing this assignment, we have a much deeper understanding of the nature of intrusion detection systems. In addition, we developed a greater appreciation for the role of a *blue team* in companies, having this project closely reflect their work.   

This project showed just how challenging it is to defend against network attacks. While our script detects the vanilla version of each attack, there are certainly a litany of ways to spoof our intrusion detection system. Despite this, we do acknowledge that our program could forseeably grow into a sophisticated, industrial-grade intrusion detection system. The industrial intrusion detection systems.  

\newpage
# 7 Recommendations


[respondertest]:pics\screenshotresponder.JPG "Responder Test"( width=70% )
[acktest]:pics\nmapacktest.png "ACK Scan Test"( width=70% )
[syntest]:pics\nmapsyntest.png "SYN Scan Test"( width=70% )
[xmastest]:pics\nmapxmastest.png "XMAS Scan Test"( width=70% )
[ettercaptest]:pics\ettercaptest.png "Ettercap Test"( width=70% )
[ettercapfound]:pics\ettercapfound.png "Ettercap Test"( width=70% )
[ettercapcmd]:pics\ettercapfound.png "Ettercap Test"( width=70% )
[syngood]:pics\syngood.png "SYN Scan Test"( width=70% )
[ackgood]:pics\ackood.png "ACK Scan Test"( width=70% )
[xmasgood]:pics\xmasgood.png "XMAS Scan Test"( width=70% )

