import pyshark

# During live capture, filter by protocols NBNS
# *** Usually, DNS is used to resolve domain names.
# *** When DNS fails, Windows uses LLMNR (Link-Local Multicast Name Resolution) to resolve names
# *** If even LLMNR fails, NBNS (NetBIO Name Service) - which uses UDP - is used for name resolution
# *** Responder takes advantage of this by listening for NBNS and LLMNR queries.
# *** Responder then responds to those queries, claiming to be the domain the victim is searching for.
# *** If an NBNS query is detected, followed immediately by a response from a valid IP, a Responder attack has occurred.

# Start live capture (change interface when needed)
cap = pyshark.LiveCapture(interface='eth0', display_filter='nbns')

# Find when Responder intrudes communication by finding its signature name "RESPPROXYSRV"
for packet in cap.sniff_continuously():
	if packet.nbns.name.find('RESPPROXYSRV'):
		print("RESPONDER ATTACK DETECTED!!")
		break