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

**Our script, that utilizes *anomaly* and *signature* based itrusion detection, does successfully detects a variety of attacks.**


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
   - Scripts: !!!**INSERT SCRIPTS**!!! 
   

##### Defender machine specifications:  

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
   `tcp && tcp.flags.fin == 1 && (tcp.window_size==1024 || tcp.window_size==2048 || tcp.window_size==3072 || tcp.window_size==4096)`  

![Initial SYN Scan][synscan]\  


### 3.1.2 ACK Scan



![Initial ACK Scan][ackscan]\  


### 3.1.3 XMAS Scan

Because XMAS scans utilize several TCP flags in an otherwise uncommon combonation, we can detect XMAS scan packets by simply checking the size of the TCP flags and which flags are currently set (FIN, PSH, URG): 
   `tcp && tcp.flags==0x29 && tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1`  

![Initial XMAS Scan][xmasscan]\


## 3.2 Ettercap

To learn how to detect a man-in-the-middle attack from Ettercap, we firt ran the attack on our  

## 3.3 Responder

## 3.4 Metasploit - CVE-2017-010 - ms17_010_psexec

\newpage
# 4 Code Explanation

## 4.1 NMAP Detection  

## 4.2 Ettercap Detection

Ettercap is a piece of software that can facilitate **Man-in-the-Middle** attacks. In order to accomplish this, ettercap first performs **ARP Cache Poisoning** which is what we decided to detect.  


```python
# Detection of ARP Cache Poisoning

#Pyshark allows python integration with Wireshark
import pyshark

#Instantiate live capture over eth0.
#Filters duplicate-address-frame
capture = pyshark.LiveCapture(
        interface='eth0', 
        display_filter='arp.duplicate-address-frame')

#If caught, this means ARP Cache Poisoning has occurred
for packet in capture.sniff_continuously():
    print("ARP CACHE POISONING DETECTED")
    print("Attacker Machine:", str(packet.ip.src))

```

## 4.3 Responder Detection

## 4.4 Metasploit Detection


\newpage
# 5 Testing and Packet Capture  

\newpage
# 6 Conclusions

\newpage
# 7 Recommendations


[ackscan]:pics\NMAPpcaptest.png "NMAP Test"( width=70% )   



