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

##### Server (Attacker) machine specifications:

   - Operating System: **Kali Linux**  
   - Server Location: **Shelby 2129**  
   - IP Address: **192.168.x.30**  
   - `python3 --version`: **`Python 3.6.7`**

##### Client (victim) machine specifications:  

   - Operating System: **Microsoft Windows 10**
   - Server Location: **Shelby 2129**  
   - IP Address: **192.168.x.40**  
   - `python3 --version`: **`Python 3.6.7`**  

\newpage
# 3 Information Discovery

In order to create a program that detects specific attacks, we conducted some exploritory tests. For each script, we ran the attack with wireshark in the backround so we could analyze the unique aspects of the attack with the goal of reverse engineering a detection scheme.

## 3.1 NMAP

## 3.2 Ettercap

## 3.3 Responder

## 3.4 Metasploit - CVE-2017-010 - ms17_010_psexec

\newpage
# 4 Code Explanation

\newpage
# 5 Testing and Packet Capture  

\newpage
# 6 Conclusions

\newpage
# 7 Recommendations
