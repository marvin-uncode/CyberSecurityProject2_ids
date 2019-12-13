#imports pyshark library
import pyshark

#runs live instance of wireshark capture
capture = pyshark.LiveCapture(display_filter='smb')

#continuously loops through packets
for packet in capture:
    
    #filters wireshark capture for Multiplex ids 65, 64, 81, 82 and nt status
    #alerts and prints attacker ip address (the first instance of the correct Multiplex ID due to first request by attacker sent
    if (packet.smb.mid == '65' or packet.smb.mid == '64' or packet.smb.mid == '81' or packet.smb.mid == '82') and (packet.smb.nt_status == '0'):
        print("ETERNAL BLUE DETECTED")
        print("Attacker Machine:", str(packet.ip.src))

capture.sniff()